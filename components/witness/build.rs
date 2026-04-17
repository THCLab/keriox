use std::process::Command;

fn main() {
    // Get the short git SHA
    let sha = Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string());

    // Check if the working tree is dirty
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

    // Re-run if git HEAD changes
    println!("cargo:rerun-if-changed=../../.git/HEAD");
    println!("cargo:rerun-if-changed=../../.git/index");
}
