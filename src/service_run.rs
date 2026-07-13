//! Platform-independent core of the Windows SCM service run loop.
//!
//! Registering a service in the SCM is not enough: the executable the SCM launches must report
//! `SERVICE_RUNNING` within ~30s or the SCM kills it with **error 1053** ("the service did not
//! respond … in a timely fashion"). The rule that avoids 1053 is simple but easy to regress:
//! report `RUNNING` **before** any slow or fallible startup work (config load, node resolution,
//! socket binds) — never after.
//!
//! That ordering is encoded HERE, behind the [`ServiceStatusReporter`] trait, so it is
//! unit-tested on EVERY platform (Linux CI included) rather than only in the Windows-only
//! [`crate::win_service`] dispatcher glue. The real Windows dispatcher supplies a reporter that
//! writes to the `windows-service` status handle; tests supply a recording mock and assert the
//! order. Keeping the contract in a testable seam is the regression guard for #499.

/// The two status transitions the SCM run loop reports. Behind a trait so the ORDER
/// (`RUNNING` before any work; `STOPPED` always reported at the end with an exit code) is
/// unit-tested with a recording mock — CI never needs a real SCM.
pub trait ServiceStatusReporter {
    /// Report `SERVICE_RUNNING`. MUST be signalled before any slow/fallible startup work so the
    /// SCM never times the service out with error 1053.
    fn report_running(&self) -> std::io::Result<()>;

    /// Report `SERVICE_STOPPED`, carrying a Win32 exit code (`0` = clean stop, non-zero = a
    /// failed run so `sc query` reflects it). Best-effort — a stopped service that cannot report
    /// has nothing left to do, so this returns `()` rather than an error.
    fn report_stopped(&self, exit_code: u32);
}

/// Run the service body under the SCM lifecycle contract: report `RUNNING`, run `body`, then
/// report `STOPPED` with an exit code derived from `body`'s result (`0` on `Ok`, `1` on `Err`).
///
/// `RUNNING` is reported BEFORE `body` executes, so no amount of slow or failing startup work
/// inside `body` — loading config, walking the node-resolution ladder, binding `:53`/`:80` —
/// can delay the `RUNNING` signal. This is the fix for Windows error 1053: the SCM sees the
/// service healthy immediately, and the bring-up proceeds afterwards. A `body` error is
/// surfaced (returned to the caller AND reflected in the stopped exit code), never swallowed and
/// never a hang.
///
/// If `report_running` itself fails the body is NOT run (there is no live SCM channel to serve
/// under) and the error is returned; there is nothing to report stopped to.
pub fn run_reporting<R, B>(reporter: &R, body: B) -> std::io::Result<()>
where
    R: ServiceStatusReporter,
    B: FnOnce() -> std::io::Result<()>,
{
    reporter.report_running()?;
    let result = body();
    reporter.report_stopped(if result.is_ok() { 0 } else { 1 });
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    /// A recording reporter: logs every transition (and, for `body` work, an interleaved
    /// `"work"` marker) so a test can assert `RUNNING` precedes the work and `STOPPED` follows.
    struct RecordingReporter {
        events: RefCell<Vec<String>>,
        fail_running: bool,
        stopped_exit: RefCell<Option<u32>>,
    }

    impl RecordingReporter {
        fn new() -> Self {
            Self {
                events: RefCell::new(Vec::new()),
                fail_running: false,
                stopped_exit: RefCell::new(None),
            }
        }
        fn with_failing_running() -> Self {
            Self {
                fail_running: true,
                ..Self::new()
            }
        }
        fn events(&self) -> Vec<String> {
            self.events.borrow().clone()
        }
    }

    impl ServiceStatusReporter for RecordingReporter {
        fn report_running(&self) -> std::io::Result<()> {
            if self.fail_running {
                return Err(std::io::Error::other("cannot report running"));
            }
            self.events.borrow_mut().push("running".into());
            Ok(())
        }
        fn report_stopped(&self, exit_code: u32) {
            self.events
                .borrow_mut()
                .push(format!("stopped:{exit_code}"));
            *self.stopped_exit.borrow_mut() = Some(exit_code);
        }
    }

    #[test]
    fn running_is_reported_before_the_body_runs() {
        let reporter = RecordingReporter::new();
        let out = run_reporting(&reporter, || {
            reporter.events.borrow_mut().push("work".into());
            Ok(())
        });
        assert!(out.is_ok());
        // The whole point of the 1053 fix: RUNNING is signalled FIRST, then the (slow) work,
        // then STOPPED — in that exact order.
        assert_eq!(reporter.events(), vec!["running", "work", "stopped:0"]);
    }

    #[test]
    fn a_body_error_still_reports_running_first_then_stopped_nonzero() {
        // Simulates a startup failure (e.g. both gateway binds failing): RUNNING must ALREADY
        // have been reported (so the SCM never 1053s), and the failure surfaces as a non-zero
        // stopped exit + the returned error — a clean, diagnosable stop, never a hang.
        let reporter = RecordingReporter::new();
        let out = run_reporting(&reporter, || {
            reporter.events.borrow_mut().push("work".into());
            Err(std::io::Error::other("bind failed"))
        });
        assert!(out.is_err());
        assert_eq!(reporter.events(), vec!["running", "work", "stopped:1"]);
        assert_eq!(*reporter.stopped_exit.borrow(), Some(1));
    }

    #[test]
    fn a_failure_to_report_running_skips_the_body_and_never_reports_stopped() {
        // If the RUNNING signal cannot be sent there is no SCM channel to serve under: the body
        // must NOT run, and nothing is reported stopped.
        let reporter = RecordingReporter::with_failing_running();
        let ran = RefCell::new(false);
        let out = run_reporting(&reporter, || {
            *ran.borrow_mut() = true;
            Ok(())
        });
        assert!(out.is_err());
        assert!(
            !*ran.borrow(),
            "body must not run when RUNNING cannot be reported"
        );
        assert!(reporter.events().is_empty());
        assert_eq!(*reporter.stopped_exit.borrow(), None);
    }
}
