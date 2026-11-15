// Copyright 2019-2024 Tauri Programme within The Commons Conservancy
// SPDX-License-Identifier: Apache-2.0
// SPDX-License-Identifier: MIT

//! Explicit Windows CEF client-DLL staging. Does not sign or qualify a sandbox.
use crate::error::{Context, bail};
use object::{Architecture, Object, ObjectKind, ObjectSection};
use std::{collections::HashMap, fs, io::Write, path::Path};
use tauri_bundler::BundleSettings;
use tauri_utils::resources::ResourcePaths;

fn architecture(target: &str) -> crate::Result<Architecture> {
  match target {
    "x86_64-pc-windows-msvc" => Ok(Architecture::X86_64),
    "aarch64-pc-windows-msvc" => Ok(Architecture::Aarch64),
    "i686-pc-windows-msvc" => Ok(Architecture::I386),
    _ => bail!("CEF Windows bootstrap requires an explicit supported MSVC target"),
  }
}

fn image(bytes: &[u8], target: &str, client: bool) -> crate::Result<()> {
  let file = object::File::parse(bytes).context("invalid Windows bootstrap PE image")?;
  if file.format() != object::BinaryFormat::Pe
    || file.architecture() != architecture(target)?
    || file.kind()
      != if client {
        ObjectKind::Dynamic
      } else {
        ObjectKind::Executable
      }
  {
    bail!("Windows bootstrap/client PE architecture or image kind differs");
  }
  if client && !file.exports().context("invalid client DLL export table")?
    .iter().any(|export| export.name() == b"RunWinMain" && file.sections().any(|section| {
      let executable = matches!(section.flags(), object::SectionFlags::Coff { characteristics } if characteristics & object::pe::IMAGE_SCN_MEM_EXECUTE != 0);
      executable && section.data().is_ok_and(|data| export.address() >= section.address()
        && export.address().checked_sub(section.address()).is_some_and(|offset| offset < data.len() as u64))
    }))
  {
    bail!("client DLL must export the CEF RunWinMain entry");
  }
  Ok(())
}

fn read_image(path: &Path, target: &str, client: bool) -> crate::Result<Vec<u8>> {
  let metadata = fs::symlink_metadata(path).context("Windows bootstrap input unavailable")?;
  if !metadata.is_file() || metadata.len() == 0 || metadata.len() > 512 * 1024 * 1024 {
    bail!("Windows bootstrap input must be a bounded regular file");
  }
  let bytes = fs::read(path).context("failed to read Windows bootstrap input")?;
  image(&bytes, target, client)?;
  Ok(bytes)
}

fn filename(name: &str) -> bool {
  let device = name.split('.').next().unwrap_or("").to_ascii_uppercase();
  let reserved_device = ["CON", "PRN", "AUX", "NUL"].contains(&device.as_str())
    || (device.len() == 4
      && (device.starts_with("COM") || device.starts_with("LPT"))
      && matches!(device.as_bytes()[3], b'1'..=b'9'));
  !name.is_empty()
    && name.len() <= 128
    && !matches!(name, "." | "..")
    && !reserved_device
    && !name.ends_with(['.', ' '])
    && !name
      .chars()
      .any(|c| c.is_control() || "/\\:<>\"|?*".contains(c))
    && !["libcef", "chrome_elf", "bootstrap", "bootstrapc"]
      .iter()
      .any(|reserved| name.eq_ignore_ascii_case(reserved))
}

/// Stage a same-name bootstrap EXE/client DLL pair in a fresh build output.
/// The original CEF bootstrap and Cargo DLL remain unchanged. Existing outputs
/// are never overwritten; choose an isolated Cargo target per release candidate.
/// Partial writes are retained and cannot be mistaken for a completed candidate.
pub(crate) fn stage(
  distribution: &Path,
  client: &Path,
  output_exe: &Path,
  target: &str,
) -> crate::Result<()> {
  let name = output_exe
    .file_stem()
    .and_then(|n| n.to_str())
    .context("invalid bootstrap output name")?;
  if !filename(name) || output_exe.extension().and_then(|e| e.to_str()) != Some("exe") {
    bail!("invalid Windows bootstrap executable name");
  }
  let output_dll = output_exe.with_extension("dll");
  let same_dll = client == output_dll;
  if output_exe
    .parent()
    .context("bootstrap output parent missing")?
    .canonicalize()?
    != client
      .parent()
      .context("Cargo DLL parent missing")?
      .canonicalize()?
  {
    bail!("Windows bootstrap must stay in the Cargo output directory");
  }
  // Validate both inputs completely before creating either output.
  let dll = read_image(client, target, true)?;
  let bootstrap = read_image(&distribution.join("bootstrap.exe"), target, false)?;
  if fs::symlink_metadata(output_exe).is_ok()
    || (!same_dll && fs::symlink_metadata(&output_dll).is_ok())
  {
    bail!("Windows bootstrap output already exists; use a fresh isolated Cargo target directory");
  }
  if output_exe
    .parent()
    .context("bootstrap output parent missing")?
    .canonicalize()?
    == distribution.canonicalize()?
  {
    bail!("bootstrap output cannot replace the CEF distribution");
  }
  let write_new = |path: &Path, bytes: &[u8]| -> crate::Result<()> {
    let mut file = fs::OpenOptions::new()
      .write(true)
      .create_new(true)
      .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
  };
  if !same_dll {
    write_new(&output_dll, &dll)?;
  }
  write_new(output_exe, &bootstrap)?;
  Ok(())
}

/// Bundling a partial/stale stage must not succeed merely because files exist.
/// Verify before the bundler performs its authorized metadata/signature changes.
pub(crate) fn verify_pair(
  distribution: &Path,
  client: &Path,
  executable: &Path,
  target: &str,
) -> crate::Result<()> {
  let dll = read_image(client, target, true)?;
  let staged = read_image(&executable.with_extension("dll"), target, true)?;
  let original_bootstrap = read_image(&distribution.join("bootstrap.exe"), target, false)?;
  let bootstrap = read_image(executable, target, false)?;
  if dll != staged || bootstrap != original_bootstrap {
    bail!("Windows bootstrap stage differs from its Cargo/CEF inputs; use a fresh candidate");
  }
  Ok(())
}

/// Add the client next to the bootstrap without changing existing resource
/// destinations. A conflicting custom resource is an error, never a replacement.
pub(crate) fn add_client_resource(
  settings: &mut BundleSettings,
  client: &Path,
) -> crate::Result<()> {
  let target = client
    .file_name()
    .and_then(|n| n.to_str())
    .context("invalid client DLL resource name")?;
  let list = settings.resources.as_deref().unwrap_or_default();
  let resources = if let Some(map) = settings.resources_map.as_ref() {
    ResourcePaths::from_map(map, true)
  } else {
    ResourcePaths::new(list, true)
  };
  let mut map = HashMap::new();
  for resource in resources.iter() {
    let resource = resource?;
    let destination = resource.target().to_string_lossy().replace('\\', "/");
    if destination.eq_ignore_ascii_case(target) {
      bail!("custom resource conflicts with the Windows CEF client DLL");
    }
    let source = resource
      .path()
      .to_str()
      .context("resource path is not Unicode")?
      .to_owned();
    if let Some(previous) = map.insert(source, destination.clone()) {
      if previous != destination {
        bail!("resource source has multiple destinations");
      }
    }
  }
  if map
    .insert(
      client
        .to_str()
        .context("client path is not Unicode")?
        .to_owned(),
      target.to_owned(),
    )
    .is_some()
  {
    bail!("client DLL source conflicts with a custom resource");
  }
  settings.resources = None;
  settings.resources_map = Some(map);
  Ok(())
}

#[cfg(test)]
mod tests {
  use super::*;
  // Synthetic PE input, not a generated/runtime binary. One executable section
  // with a named export exercises the real PE reader without a Windows SDK.
  fn pe(dll: bool, export: bool) -> Vec<u8> {
    fn w16(bytes: &mut [u8], at: usize, value: u16) {
      bytes[at..at + 2].copy_from_slice(&value.to_le_bytes());
    }
    fn w32(bytes: &mut [u8], at: usize, value: u32) {
      bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
    }
    let mut b = vec![0; 0x600];
    b[..2].copy_from_slice(b"MZ");
    w32(&mut b, 0x3c, 0x80);
    b[0x80..0x84].copy_from_slice(b"PE\0\0");
    w16(&mut b, 0x84, 0x8664);
    w16(&mut b, 0x86, 1);
    w16(&mut b, 0x94, 0xf0);
    w16(&mut b, 0x96, if dll { 0x2022 } else { 0x22 });
    let o = 0x98;
    w16(&mut b, o, 0x20b);
    w32(&mut b, o + 16, 0x1000);
    w32(&mut b, o + 20, 0x1000);
    b[o + 24..o + 32].copy_from_slice(&0x140000000u64.to_le_bytes());
    w32(&mut b, o + 32, 0x1000);
    w32(&mut b, o + 36, 0x200);
    w32(&mut b, o + 56, 0x2000);
    w32(&mut b, o + 60, 0x200);
    w16(&mut b, o + 68, 2);
    w32(&mut b, o + 108, 16);
    let s = o + 0xf0;
    b[s..s + 5].copy_from_slice(b".text");
    w32(&mut b, s + 8, 0x400);
    w32(&mut b, s + 12, 0x1000);
    w32(&mut b, s + 16, 0x400);
    w32(&mut b, s + 20, 0x200);
    w32(&mut b, s + 36, 0x60000020);
    b[0x200] = 0xc3;
    if export {
      w32(&mut b, o + 112, 0x1100);
      w32(&mut b, o + 116, 0x100);
      w32(&mut b, 0x30c, 0x1160);
      w32(&mut b, 0x310, 1);
      w32(&mut b, 0x314, 1);
      w32(&mut b, 0x318, 1);
      w32(&mut b, 0x31c, 0x1140);
      w32(&mut b, 0x320, 0x1144);
      w32(&mut b, 0x324, 0x1148);
      w32(&mut b, 0x340, 0x1000);
      w32(&mut b, 0x344, 0x1170);
      b[0x360..0x36c].copy_from_slice(b"fixture.dll\0");
      b[0x370..0x37b].copy_from_slice(b"RunWinMain\0");
    }
    b
  }
  const TARGET: &str = "x86_64-pc-windows-msvc";

  #[test]
  fn requires_matching_architecture_image_kind_and_real_entry_export() {
    assert!(image(&pe(true, true), TARGET, true).is_ok());
    assert!(image(&pe(false, false), TARGET, false).is_ok());
    assert!(image(&pe(true, false), TARGET, true).is_err());
    assert!(image(&pe(false, true), TARGET, true).is_err());
    assert!(image(&pe(true, true), "aarch64-pc-windows-msvc", true).is_err());
    assert!(image(&pe(true, true), "x86_64-unknown-linux-gnu", true).is_err());
    assert!(image(b"not a PE image", TARGET, true).is_err());
    let mut forwarded = pe(true, true);
    forwarded[0x340..0x344].copy_from_slice(&0x1160u32.to_le_bytes());
    assert!(image(&forwarded, TARGET, true).is_err());
    let mut zero = pe(true, true);
    zero[0x340..0x344].fill(0);
    assert!(image(&zero, TARGET, true).is_err());
  }

  #[test]
  fn stages_same_name_pair_without_changing_originals_or_clobbering() {
    let root = tempfile::tempdir().unwrap();
    let dist = root.path().join("cef");
    let out = root.path().join("out");
    fs::create_dir(&dist).unwrap();
    fs::create_dir(&out).unwrap();
    let client = out.join("crate_lib.dll");
    let exe = out.join("my-app.exe");
    fs::write(&client, pe(true, true)).unwrap();
    fs::write(dist.join("bootstrap.exe"), pe(false, false)).unwrap();
    stage(&dist, &client, &exe, TARGET).unwrap();
    verify_pair(&dist, &client, &exe, TARGET).unwrap();
    assert_eq!(fs::read(&client).unwrap(), pe(true, true));
    assert_eq!(
      fs::read(dist.join("bootstrap.exe")).unwrap(),
      pe(false, false)
    );
    assert!(stage(&dist, &client, &exe, TARGET).is_err());
    fs::write(&exe, b"partial").unwrap();
    assert!(verify_pair(&dist, &client, &exe, TARGET).is_err());
    assert_eq!(fs::read(&client).unwrap(), pe(true, true));
  }

  #[test]
  fn invalid_dll_leaves_no_staged_outputs_and_escape_is_refused() {
    let root = tempfile::tempdir().unwrap();
    let dist = root.path().join("cef");
    let out = root.path().join("out");
    fs::create_dir(&dist).unwrap();
    fs::create_dir(&out).unwrap();
    let client = out.join("crate_lib.dll");
    fs::write(&client, pe(true, false)).unwrap();
    fs::write(dist.join("bootstrap.exe"), pe(false, false)).unwrap();
    assert!(stage(&dist, &client, &out.join("app.exe"), TARGET).is_err());
    assert!(!out.join("app.exe").exists() && !out.join("app.dll").exists());
    fs::write(&client, pe(true, true)).unwrap();
    assert!(stage(&dist, &client, &root.path().join("escaped.exe"), TARGET).is_err());
    assert!(!root.path().join("escaped.exe").exists());
  }

  #[test]
  fn resource_mapping_preserves_existing_assets_and_rejects_client_collision() {
    let root = tempfile::tempdir().unwrap();
    let asset = root.path().join("logo.svg");
    fs::write(&asset, b"fixture").unwrap();
    let mut settings = BundleSettings::default();
    settings.resources_map = Some(HashMap::from([(
      asset.to_str().unwrap().into(),
      "assets/logo.svg".into(),
    )]));
    add_client_resource(&mut settings, &root.path().join("app.dll")).unwrap();
    assert_eq!(
      settings.resources_map.as_ref().unwrap()[asset.to_str().unwrap()],
      "assets/logo.svg"
    );
    assert_eq!(
      settings.resources_map.as_ref().unwrap()[root.path().join("app.dll").to_str().unwrap()],
      "app.dll"
    );
    let mut conflicting = BundleSettings::default();
    conflicting.resources_map = Some(HashMap::from([(
      asset.to_str().unwrap().into(),
      "APP.DLL".into(),
    )]));
    assert!(add_client_resource(&mut conflicting, &root.path().join("app.dll")).is_err());
    assert_eq!(
      conflicting.resources_map.as_ref().unwrap()[asset.to_str().unwrap()],
      "APP.DLL"
    );
  }

  #[test]
  fn unsafe_windows_names_are_not_output_candidates() {
    for name in [
      "",
      ".",
      "..",
      "app/other",
      "app\\other",
      "C:app",
      "app.",
      "app ",
      "NUL",
      "COM1.app",
      "libcef",
      "bootstrap",
    ] {
      assert!(!filename(name), "{name}");
    }
    assert!(filename("Mithril Store"));
  }
}
