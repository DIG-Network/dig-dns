//! Trusted resolution of system-tool paths for elevated spawns (dig_ecosystem #657).
//!
//! Every `dig-dns` code path that shells out to an OS tool while running elevated (the service
//! registration in [`crate::service`], the `configure-os` resolver wiring in [`crate::os_config`],
//! and the read-only probes in [`crate::doctor`]) MUST spawn that tool by its **absolute** path,
//! never its bare name. Windows resolves a bare command name via a search order in which the
//! CURRENT DIRECTORY precedes `System32`, so an elevated run with an attacker-controlled working
//! directory could execute a planted `sc.exe` / `net.exe` / `powershell.exe` instead of the real
//! one. Unix is less exposed (no implicit-CWD lookup), but pinning the canonical `/usr/bin`-family
//! path is the same defense and removes any dependence on the inherited `PATH`.
//!
//! [`resolve_system_tool`] is the single chokepoint: it ALWAYS returns an absolute path — an
//! unknown or not-found tool falls back to a canonical absolute candidate, never the bare name.
//!
//! On Windows the system directory is obtained from the Win32 [`GetSystemDirectoryW`] API rather
//! than the `%SystemRoot%` environment variable, so a caller cannot redirect the resolver by
//! poisoning the environment; the env var is only a last-resort fallback if the syscall fails.
//!
//! [`GetSystemDirectoryW`]: https://learn.microsoft.com/windows/win32/api/sysinfoapi/nf-sysinfoapi-getsystemdirectoryw

/// Resolve a known system tool's bare `name` to a trusted ABSOLUTE path so an elevated spawn can
/// never be hijacked by a search-order-planted binary. The result is ALWAYS absolute.
///
/// - **Windows** — built under the real system directory (from [`system_directory`], normally
///   `C:\Windows\System32`); PowerShell resolves to its `WindowsPowerShell\v1.0\powershell.exe`.
/// - **Unix** — the first existing candidate across the canonical `/usr/bin`, `/bin`, `/usr/sbin`,
///   `/sbin` locations (per [`system_tool_candidates`]), else the first (still-absolute) candidate.
pub fn resolve_system_tool(name: &str) -> String {
    #[cfg(windows)]
    {
        let system32 = system_directory();
        match name {
            "powershell" => format!(r"{system32}\WindowsPowerShell\v1.0\powershell.exe"),
            // `sc.exe`/`net.exe`/`reg.exe` etc. all live directly in System32.
            other => {
                let stem = other.strip_suffix(".exe").unwrap_or(other);
                format!(r"{system32}\{stem}.exe")
            }
        }
    }
    #[cfg(not(windows))]
    {
        let candidates = system_tool_candidates(name);
        candidates
            .iter()
            .find(|p| std::path::Path::new(p).exists())
            .cloned()
            .unwrap_or_else(|| candidates[0].clone())
    }
}

/// The Windows system directory (`C:\Windows\System32` on a stock install), queried from the
/// Win32 `GetSystemDirectoryW` syscall so it cannot be redirected by a poisoned `%SystemRoot%`.
/// Falls back to `%SystemRoot%\System32` (then a hard-coded `C:\Windows\System32`) only if the
/// syscall reports failure — a defense-in-depth path that should never be taken in practice.
///
/// The call into `GetSystemDirectoryW` is `unsafe` FFI; it is sound because the buffer is a fixed
/// stack array, its length is passed as the API's `uSize`, and the returned character count is
/// validated to be within the buffer before it is read back.
#[cfg(windows)]
fn system_directory() -> String {
    use windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW;

    // MAX_PATH (260) is the documented upper bound for the system directory path.
    let mut buf = [0u16; 260];
    // SAFETY: `buf` is a valid, writable slice of `buf.len()` UTF-16 units; `GetSystemDirectoryW`
    // writes at most `uSize` units and returns the count actually written (excluding the NUL). We
    // read back only the validated `len` units below.
    let len = unsafe { GetSystemDirectoryW(buf.as_mut_ptr(), buf.len() as u32) };
    if len > 0 && (len as usize) <= buf.len() {
        return String::from_utf16_lossy(&buf[..len as usize]);
    }
    let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_string());
    format!(r"{root}\System32")
}

/// The canonical absolute-path candidates for a Unix system tool, most-preferred first. Every
/// candidate is absolute, so the [`resolve_system_tool`] fallback stays absolute. PURE.
#[cfg(not(windows))]
fn system_tool_candidates(name: &str) -> Vec<String> {
    let dirs: &[&str] = match name {
        // networking tools live in the sbin dirs on macOS/BSD
        "ifconfig" => &["/sbin", "/usr/sbin"],
        // launchctl is macOS-only, in /bin
        "launchctl" => &["/bin", "/usr/bin"],
        _ => &["/usr/bin", "/bin", "/usr/sbin", "/sbin"],
    };
    dirs.iter().map(|d| format!("{d}/{name}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_system_tool_is_always_absolute_never_a_bare_name() {
        for tool in [
            "sc",
            "net",
            "id",
            "systemctl",
            "launchctl",
            "powershell",
            "reg",
        ] {
            let resolved = resolve_system_tool(tool);
            assert_ne!(resolved, tool, "{tool} must not resolve to its bare name");
            #[cfg(windows)]
            assert!(
                resolved.contains(r"\") && resolved.len() > 3 && &resolved[1..3] == r":\",
                "{tool} -> {resolved} must be an absolute Windows path"
            );
            #[cfg(not(windows))]
            assert!(
                resolved.starts_with('/'),
                "{tool} -> {resolved} must be an absolute Unix path"
            );
        }
    }

    #[test]
    #[cfg(windows)]
    fn resolve_system_tool_lands_under_the_real_system32() {
        // The system directory comes from GetSystemDirectoryW, so its casing is whatever the OS
        // reports (`System32` vs `system32`); compare case-insensitively.
        let lc = |t: &str| resolve_system_tool(t).to_ascii_lowercase();
        assert!(lc("sc").ends_with(r"\system32\sc.exe"));
        assert!(lc("net").ends_with(r"\system32\net.exe"));
        assert!(lc("reg").ends_with(r"\system32\reg.exe"));
        // A caller passing the ".exe" suffix must not double it.
        assert!(lc("sc.exe").ends_with(r"\system32\sc.exe"));
        assert!(!lc("sc.exe").contains(".exe.exe"));
        assert!(lc("powershell").ends_with(r"\system32\windowspowershell\v1.0\powershell.exe"));
    }

    #[test]
    #[cfg(not(windows))]
    fn resolve_system_tool_prefers_canonical_bin_dirs() {
        // `id` exists on any Unix test host — it must resolve to a real absolute path.
        let id = resolve_system_tool("id");
        assert!(id.starts_with('/') && id.ends_with("/id"));
        // An unknown tool still yields an absolute (first-candidate) path, never a bare name.
        assert!(resolve_system_tool("definitely-not-a-tool").starts_with("/usr/bin/"));
    }
}
