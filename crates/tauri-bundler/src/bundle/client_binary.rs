// Copyright 2019-2024 Tauri Programme within The Commons Conservancy
// SPDX-License-Identifier: Apache-2.0
// SPDX-License-Identifier: MIT

use anyhow::{Context, bail};
use std::{
  fs,
  io::{Read, Seek, SeekFrom, Write},
  path::{Path, PathBuf},
};

/// Marker retained after an interrupted Windows CEF client mutation. An owner
/// must reconcile the candidate before it can be bundled again.
pub fn windows_cef_bundle_marker(client: &Path) -> PathBuf {
  client.with_extension("dll.tauri-bundle-in-progress")
}

/// The staged client is a separate copy: the original Cargo DLL is never
/// mutated. Normal errors/unwinds restore the stage atomically; abort/kill or
/// failed restoration retain a marker and a named recovery copy, not success.
pub(super) struct ClientBinary {
  path: PathBuf,
  marker: PathBuf,
  backup: Option<tempfile::NamedTempFile>,
  permissions: fs::Permissions,
}

impl ClientBinary {
  pub(super) fn new(path: &Path) -> anyhow::Result<Self> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() {
      bail!("CEF client must be a regular staged file");
    }
    let parent = path.parent().context("CEF client parent missing")?;
    let marker = windows_cef_bundle_marker(path);
    if fs::symlink_metadata(&marker).is_ok() {
      bail!("interrupted CEF bundle requires owner reconciliation");
    }
    let mut backup = tempfile::Builder::new()
      .prefix(".tauri-cef-recovery-")
      .tempfile_in(parent)?;
    // Retention does not depend on a fallible rename in a destructor.
    backup.disable_cleanup(true);
    let mut source = fs::File::open(path)?;
    std::io::copy(&mut source, backup.as_file_mut())?;
    backup.as_file_mut().sync_all()?;
    // Create the marker before any patch or signer is allowed to modify data.
    let mut record = fs::OpenOptions::new()
      .write(true)
      .create_new(true)
      .open(&marker)?;
    writeln!(
      record,
      "recovery={}",
      backup
        .path()
        .file_name()
        .context("recovery name missing")?
        .to_string_lossy()
    )?;
    record.sync_all()?;
    Ok(Self {
      path: path.into(),
      marker,
      backup: Some(backup),
      permissions: metadata.permissions(),
    })
  }

  pub(super) fn restore(&mut self) -> anyhow::Result<()> {
    let backup = self.backup.as_mut().context("CEF recovery copy missing")?;
    let mut replacement =
      tempfile::NamedTempFile::new_in(self.path.parent().context("CEF client parent missing")?)?;
    backup.as_file_mut().seek(SeekFrom::Start(0))?;
    std::io::copy(backup.as_file_mut(), replacement.as_file_mut())?;
    replacement
      .as_file_mut()
      .set_permissions(self.permissions.clone())?;
    replacement.as_file_mut().sync_all()?;
    replacement
      .persist(&self.path)
      .map_err(|error| error.error)?;
    // Read back the full original content, not just size or file existence.
    let mut restored = fs::File::open(&self.path)?;
    backup.as_file_mut().seek(SeekFrom::Start(0))?;
    let mut a = [0; 65536];
    let mut b = [0; 65536];
    loop {
      let na = restored.read(&mut a)?;
      // read_exact allows independent short reads of the backup descriptor.
      backup.as_file_mut().read_exact(&mut b[..na])?;
      if a[..na] != b[..na] {
        bail!("CEF client restoration readback differs");
      }
      if na == 0 {
        if backup.as_file_mut().read(&mut b[..1])? != 0 {
          bail!("CEF client restoration truncated");
        }
        break;
      }
    }
    Ok(())
  }

  pub(super) fn finish(&mut self) -> anyhow::Result<()> {
    self.restore()?;
    fs::remove_file(&self.marker)?;
    if let Some(backup) = &mut self.backup {
      backup.disable_cleanup(false);
    }
    self.backup = None;
    Ok(())
  }
}

impl Drop for ClientBinary {
  fn drop(&mut self) {
    if self.backup.is_none() {
      return;
    }
    let restored = self.restore().and_then(|_| {
      fs::remove_file(&self.marker)?;
      Ok(())
    });
    if let Some(backup) = &mut self.backup {
      match restored {
        Ok(()) => backup.disable_cleanup(false),
        Err(error) => log::error!(
          "CEF client recovery required at {}: {error}",
          backup.path().display()
        ),
      }
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  #[test]
  fn ordinary_error_and_unwind_restore_partial_mutations() {
    for panic in [false, true] {
      let root = tempfile::tempdir().unwrap();
      let path = root.path().join("app.dll");
      fs::write(&path, b"original client").unwrap();
      let outcome = std::panic::catch_unwind(|| -> anyhow::Result<()> {
        let _guard = ClientBinary::new(&path)?;
        fs::write(&path, b"partial")?;
        if panic {
          panic!("synthetic signer panic");
        }
        bail!("synthetic package failure")
      });
      assert!(if panic {
        outcome.is_err()
      } else {
        outcome.unwrap().is_err()
      });
      assert_eq!(fs::read(&path).unwrap(), b"original client");
      assert!(!windows_cef_bundle_marker(&path).exists());
    }
  }

  #[test]
  fn failed_restore_keeps_recovery_copy_and_blocks_next_owner() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("app.dll");
    fs::write(&path, b"original client").unwrap();
    let mut guard = ClientBinary::new(&path).unwrap();
    let recovery = guard.backup.as_ref().unwrap().path().to_owned();
    // Only this test's synthetic file is replaced by a directory to force a
    // replacement error without deleting any real candidate or evidence.
    fs::remove_file(&path).unwrap();
    fs::create_dir(&path).unwrap();
    assert!(guard.restore().is_err());
    drop(guard);
    assert_eq!(fs::read(&recovery).unwrap(), b"original client");
    assert!(windows_cef_bundle_marker(&path).is_file());
    fs::remove_dir(&path).unwrap();
    fs::write(&path, b"unknown stage").unwrap();
    assert!(ClientBinary::new(&path).is_err());
    assert_eq!(fs::read(&path).unwrap(), b"unknown stage");
  }

  #[test]
  fn interrupted_without_drop_retains_marker_and_recovery() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("app.dll");
    fs::write(&path, b"original client").unwrap();
    let guard = ClientBinary::new(&path).unwrap();
    let recovery = guard.backup.as_ref().unwrap().path().to_owned();
    fs::write(&path, b"unknown interrupted mutation").unwrap();
    // Models process abort/kill, which cannot run Rust Drop. This is not a
    // claim that a unit test executes a real OS-level process crash.
    std::mem::forget(guard);
    assert!(ClientBinary::new(&path).is_err());
    assert_eq!(fs::read(recovery).unwrap(), b"original client");
    assert_eq!(fs::read(path).unwrap(), b"unknown interrupted mutation");
  }
}
