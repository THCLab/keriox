use std::process::Command;

fn main() {
    // Allow override via environment variable (useful for Docker builds
    // where .git is not available: pass GIT_VERSION_SUFFIX as a build arg).
    if std::env::var("GIT_VERSION_SUFFIX").is_ok() {
        // Cargo will forward it as-is since it's already set.
        println!(
            "cargo:rustc-env=GIT_VERSION_SUFFIX={}",
            std::env::var("GIT_VERSION_SUFFIX").unwrap()
        );
    } else {
        // Try to detect from git
        let sha = Command::new("git")
            .args(["rev-parse", "--short", "HEAD"])
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string());

        let dirty = Command::new("git")
            .args(["status", "--porcelain"])
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| !o.stdout.is_empty())
            .unwrap_or(false);

        if let Some(sha) = sha {
            let suffix = if dirty {
                format!("-dirty-{sha}")
            } else {
                format!("-{sha}")
            };
            println!("cargo:rustc-env=GIT_VERSION_SUFFIX={suffix}");
        } else if dirty {
            println!("cargo:rustc-env=GIT_VERSION_SUFFIX=-dirty");
        }
    }

    // Re-run if git HEAD changes (no-op when .git is absent)
    println!("cargo:rerun-if-changed=../../.git/HEAD");
    println!("cargo:rerun-if-changed=../../.git/index");
    println!("cargo:rerun-if-env-changed=GIT_VERSION_SUFFIX");
}
