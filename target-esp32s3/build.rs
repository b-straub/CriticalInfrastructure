use std::process::Command;

/// Trimmed stdout of a successful command, else `None`.
fn run(cmd: &str, args: &[&str]) -> Option<String> {
    let out = Command::new(cmd).args(args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8(out.stdout).ok()?.trim().to_string();
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

fn main() {
    println!("cargo:rustc-link-search={}", std::env::var("CARGO_MANIFEST_DIR").unwrap());
    println!("cargo:rustc-link-arg-bins=-Tlinkall.x");

    // Re-run this script on EVERY build so the version/timestamp below reflect *this* build,
    // not a cached one. Referencing a path that never exists makes Cargo unable to prove the
    // script is up to date, so it re-runs it each time. Without this, an unchanged source tree
    // reuses the cached stamp and an OTA of "the same code" shows the old tag.
    println!("cargo:rerun-if-changed=.always-rebuild");

    // Firmware version + build time, so the app can show which build is running (handy for
    // confirming an OTA landed). Runs on the host at build time. No rerun-if directives:
    // cargo re-runs this whenever the crate is rebuilt, so the values track the build.
    let hash = run("git", &["rev-parse", "--short=7", "HEAD"]).unwrap_or_else(|| "nogit".into());
    let dirty = run("git", &["status", "--porcelain"]).is_some();
    let version = if dirty { format!("{hash}+") } else { hash };
    let build = run("date", &["+%Y-%m-%d %H:%M"]).unwrap_or_else(|| "unknown".into());
    let hhmm = run("date", &["+%H%M"]).unwrap_or_else(|| "----".into()); // compact LCD tag
    println!("cargo:rustc-env=FW_VERSION={version}");
    println!("cargo:rustc-env=FW_BUILD={build}");
    println!("cargo:rustc-env=FW_HHMM={hhmm}");
}
