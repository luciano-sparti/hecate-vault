use anyhow::{Context, Result};
use std::collections::HashMap;
use std::process::Command;

/// Spawns a child process with temporary injected environment variables.
pub fn execute_with_secrets(
    command: &str,
    args: &[String],
    env_secrets: &HashMap<String, String>,
) -> Result<i32> {
    let mut cmd = Command::new(command);
    cmd.args(args);

    // Inject decrypted secrets into the child process environment
    for (k, v) in env_secrets {
        cmd.env(k, v);
    }

    let mut child = cmd
        .spawn()
        .with_context(|| format!("Failed to spawn command '{}'", command))?;

    let status = child.wait().context("Child process failed during execution")?;

    Ok(status.code().unwrap_or(-1))
}
