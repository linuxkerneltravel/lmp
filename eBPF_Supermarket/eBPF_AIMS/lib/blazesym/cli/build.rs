use anyhow::Result;

use grev::git_revision_auto;


fn main() -> Result<()> {
    let dir = env!("CARGO_MANIFEST_DIR");
    if let Some(git_rev) = git_revision_auto(dir)? {
        println!(
            "cargo:rustc-env=VERSION={} ({})",
            env!("CARGO_PKG_VERSION"),
            git_rev
        );
    } else {
        println!("cargo:rustc-env=VERSION={}", env!("CARGO_PKG_VERSION"));
    }
    Ok(())
}
