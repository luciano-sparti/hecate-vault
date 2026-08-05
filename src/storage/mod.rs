use anyhow::{Context, Result};
use fd_lock::RwLock;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use tempfile::NamedTempFile;


/// Resolves default path to vault file (`~/.hecate/vault.json` or custom path).
pub fn default_vault_path() -> Result<PathBuf> {
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .context("Could not determine user home directory")?;
    
    let dir = PathBuf::from(home).join(".hecate");
    if !dir.exists() {
        fs::create_dir_all(&dir).context("Failed to create ~/.hecate directory")?;
    }

    Ok(dir.join("vault.json"))
}

/// Atomically write data to target path using temp file replacement and file locking.
pub fn atomic_write_file(path: &Path, content: &[u8]) -> Result<()> {
    let parent_dir = path
        .parent()
        .context("Vault target path does not have a parent directory")?;

    if !parent_dir.exists() {
        fs::create_dir_all(parent_dir)?;
    }

    let mut temp_file = NamedTempFile::new_in(parent_dir)
        .context("Failed to create temporary file for atomic write")?;
    
    temp_file.write_all(content)?;
    temp_file.flush()?;

    temp_file
        .persist(path)
        .context("Failed to atomically replace target file")?;

    Ok(())
}

/// Safely read a file under a shared read lock.
pub fn read_file_locked(path: &Path) -> Result<Vec<u8>> {
    let file = File::open(path)
        .with_context(|| format!("Failed to open vault file at {:?}", path))?;
    
    let lock = RwLock::new(file);
    let guard = lock.read().context("Failed to acquire read lock on vault file")?;
    
    let mut contents = Vec::new();
    (&*guard).read_to_end(&mut contents)?;
    Ok(contents)
}

