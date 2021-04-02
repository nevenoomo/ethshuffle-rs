use std::process::Command;

fn main() {
    // Update and init git submodules
    Command::new("git")
        .args(&["submodule", "update", "--init"])
        .status()
        .expect("Failed to update submodules.");
}
