//! Windows Service Control Protocol entrypoint (Windows only).
//!
//! Registering a service in the SCM (via `service-manager`) is not enough: the executable the
//! SCM launches must itself connect back to the SCM (`StartServiceCtrlDispatcher`) and report
//! `Running` within ~30s, or the SCM kills it with error 1053 ("the service did not respond …
//! in a timely fashion"). This module is that connection: the installed service runs `dig-dns
//! run-service`, which calls [`run`] here to become a real Windows service — registering a
//! control handler, reporting `Running`, serving until the SCM sends `Stop`, then reporting
//! `Stopped`.
//!
//! **The 1053 fix (SPEC §13.4):** `Running` is reported FIRST, before ANY slow or fallible
//! startup work — config load, tokio-runtime build, node resolution, or the `:80`/`:53` socket
//! binds. That ordering lives in the platform-independent [`crate::service_run::run_reporting`]
//! seam (unit-tested with a recording mock on every platform), and this module only adapts the
//! SCM status handle to it via [`ScmReporter`]. So the "report RUNNING before work" contract is
//! covered by tests that never need a real SCM, and can never silently regress.
//!
//! The service is registered under the qualified label ([`crate::service::SERVICE_LABEL`]); the
//! name passed to the dispatcher must match it exactly.

use std::ffi::OsString;
use std::sync::mpsc;
use std::time::Duration;

use windows_service::service::{
    ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{
    self, ServiceControlHandlerResult, ServiceStatusHandle,
};
use windows_service::{define_windows_service, service_dispatcher};

use crate::config;
use crate::server::serve_with_shutdown;
use crate::service::SERVICE_LABEL;
use crate::service_run::{run_reporting, ServiceStatusReporter};

const SERVICE_TYPE: ServiceType = ServiceType::OWN_PROCESS;

/// Hand control to the SCM dispatcher. Blocks until the service stops. Called by the
/// `run-service` subcommand (the program the installed service launches). On a dispatcher error
/// (e.g. invoked outside the SCM) it returns an `io::Error` so the CLI can report it.
pub fn run() -> std::io::Result<()> {
    service_dispatcher::start(SERVICE_LABEL, ffi_service_main)
        .map_err(|e| std::io::Error::other(e.to_string()))
}

// Generates `ffi_service_main`, the low-level entry the SCM calls, which forwards to
// `service_main` below.
define_windows_service!(ffi_service_main, service_main);

/// Service entry called on a background thread by the SCM. There is no stdout/stderr here, so
/// failures are surfaced only by the reported service status (a failed startup leaves the SCM
/// seeing a stopped service with a non-zero exit code).
fn service_main(_args: Vec<OsString>) {
    if let Err(e) = run_service() {
        eprintln!("dig-dns service error: {e}");
    }
}

/// Adapts the Windows SCM status handle to the platform-independent [`ServiceStatusReporter`],
/// so the RUNNING-before-work ordering (SPEC §13.4, the 1053 fix) is driven by the SAME
/// [`run_reporting`] code path the unit tests exercise — this file only maps a report to a
/// `set_service_status` call.
struct ScmReporter {
    handle: ServiceStatusHandle,
}

impl ScmReporter {
    /// Build a [`ServiceStatus`] for `state` accepting `accept` with Win32 `exit`.
    fn status(state: ServiceState, accept: ServiceControlAccept, exit: u32) -> ServiceStatus {
        ServiceStatus {
            service_type: SERVICE_TYPE,
            current_state: state,
            controls_accepted: accept,
            exit_code: ServiceExitCode::Win32(exit),
            checkpoint: 0,
            wait_hint: Duration::default(),
            process_id: None,
        }
    }
}

impl ServiceStatusReporter for ScmReporter {
    fn report_running(&self) -> std::io::Result<()> {
        self.handle
            .set_service_status(Self::status(
                ServiceState::Running,
                ServiceControlAccept::STOP,
                0,
            ))
            .map_err(|e| std::io::Error::other(e.to_string()))
    }

    fn report_stopped(&self, exit_code: u32) {
        // Best-effort: a stopping service that cannot report has nothing left to do.
        let _ = self.handle.set_service_status(Self::status(
            ServiceState::Stopped,
            ServiceControlAccept::empty(),
            exit_code,
        ));
    }
}

/// The service body: register the control handler, report `Running` (BEFORE any slow/fallible
/// work — the 1053 fix), then load config + build the runtime + serve both `.dig` resolution
/// paths until `Stop`, reporting `Stopped` (with a non-zero exit on a bring-up failure) at the
/// end. The RUNNING-then-work ordering is enforced by [`run_reporting`].
fn run_service() -> std::io::Result<()> {
    // The control handler signals `Stop` over this channel; the serve future waits on it. It is
    // registered BEFORE `run_reporting` reports RUNNING so a Stop arriving immediately after the
    // RUNNING signal is never lost.
    let (shutdown_tx, shutdown_rx) = mpsc::channel::<()>();
    let event_handler = move |control_event| -> ServiceControlHandlerResult {
        match control_event {
            // The SCM polls for status; always succeed.
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            ServiceControl::Stop => {
                let _ = shutdown_tx.send(());
                ServiceControlHandlerResult::NoError
            }
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };
    let status_handle = service_control_handler::register(SERVICE_LABEL, event_handler)
        .map_err(|e| std::io::Error::other(e.to_string()))?;
    let reporter = ScmReporter {
        handle: status_handle,
    };

    // Report RUNNING first; then do EVERYTHING slow or fallible in the body. A body error
    // (e.g. both the primary and fallback gateway binds are held) is reported as STOPPED with a
    // non-zero exit and returned — a clean, diagnosable stop, never a hang and never a 1053.
    run_reporting(&reporter, move || {
        let config = config::from_env(|k| std::env::var(k).ok())
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e.to_string()))?;
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?;
        rt.block_on(async move {
            // Bridge the blocking std mpsc into an async shutdown future the server awaits.
            let shutdown = async move {
                let _ = tokio::task::spawn_blocking(move || shutdown_rx.recv()).await;
            };
            serve_with_shutdown(config, shutdown).await
        })
        .map_err(|e| std::io::Error::other(e.to_string()))
    })
}
