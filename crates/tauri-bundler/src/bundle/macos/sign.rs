// Copyright 2016-2019 Cargo-Bundle developers <https://github.com/burtonageo/cargo-bundle>
// Copyright 2019-2024 Tauri Programme within The Commons Conservancy
// SPDX-License-Identifier: Apache-2.0
// SPDX-License-Identifier: MIT

use std::{
  env::{var, var_os},
  ffi::OsString,
  path::PathBuf,
};

use crate::{Entitlements, Settings, error::NotarizeAuthError};

pub struct SignTarget {
  pub path: PathBuf,
  pub is_an_executable: bool,
  /// Only CEF helper apps spawned by the host inherit its App Sandbox.
  pub is_cef_helper: bool,
}

/// Main grants and identity must not be copied onto spawned sandboxed CEF helpers.
/// Non-sandboxed CEF and all other signing targets keep their existing settings.
fn target_entitlements(
  configured: Option<&Entitlements>,
  cef_helper: bool,
) -> crate::Result<Option<Entitlements>> {
  let Some(configured) = configured else {
    return Ok(None);
  };
  if !cef_helper {
    return Ok(Some(configured.clone()));
  }
  let value = match configured {
    Entitlements::Path(path) => plist::Value::from_file(path)?,
    Entitlements::Plist(value) => value.clone(),
  };
  let dictionary = value
    .as_dictionary()
    .ok_or_else(|| crate::Error::GenericError("macOS entitlements must be a dictionary".into()))?;
  let sandbox = match dictionary.get("com.apple.security.app-sandbox") {
    None | Some(plist::Value::Boolean(false)) => false,
    Some(plist::Value::Boolean(true)) => true,
    _ => {
      return Err(crate::Error::GenericError(
        "com.apple.security.app-sandbox must be a boolean".into(),
      ));
    }
  };
  if !sandbox {
    return Ok(Some(configured.clone()));
  }
  if dictionary
    .get("com.apple.security.inherit")
    .and_then(plist::Value::as_boolean)
    == Some(true)
  {
    return Err(crate::Error::GenericError(
      "the main app must not inherit its App Sandbox".into(),
    ));
  }
  let mut child = plist::Dictionary::new();
  child.insert("com.apple.security.app-sandbox".into(), true.into());
  child.insert("com.apple.security.inherit".into(), true.into());
  Ok(Some(Entitlements::Plist(child.into())))
}

pub fn keychain(identity: Option<&str>) -> crate::Result<Option<tauri_macos_sign::Keychain>> {
  if let (Some(certificate_encoded), Some(certificate_password)) = (
    var_os("APPLE_CERTIFICATE"),
    var_os("APPLE_CERTIFICATE_PASSWORD"),
  ) {
    // import user certificate - useful for CI build
    let keychain =
      tauri_macos_sign::Keychain::with_certificate(&certificate_encoded, &certificate_password)
        .map_err(Box::new)?;
    if let Some(identity) = identity {
      let certificate_identity = keychain.signing_identity();
      if !certificate_identity.contains(identity) {
        return Err(crate::Error::GenericError(format!(
          "certificate from APPLE_CERTIFICATE \"{certificate_identity}\" environment variable does not match provided identity \"{identity}\""
        )));
      }
    }
    Ok(Some(keychain))
  } else if let Some(identity) = identity {
    Ok(Some(tauri_macos_sign::Keychain::with_signing_identity(
      identity,
    )))
  } else {
    Ok(None)
  }
}

pub fn sign(
  keychain: &tauri_macos_sign::Keychain,
  targets: Vec<SignTarget>,
  settings: &Settings,
) -> crate::Result<()> {
  log::info!(action = "Signing"; "with identity \"{}\"", keychain.signing_identity());

  for target in targets {
    let entitlements =
      target_entitlements(settings.macos().entitlements.as_ref(), target.is_cef_helper)?;
    let (entitlements_path, _temp_file) = match entitlements.as_ref() {
      Some(Entitlements::Path(path)) => (Some(path.to_owned()), None),
      Some(Entitlements::Plist(plist)) => {
        let mut temp_file = tempfile::NamedTempFile::new()?;
        plist::to_writer_xml(temp_file.as_file_mut(), &plist)?;
        (Some(temp_file.path().to_path_buf()), Some(temp_file))
      }
      None => (None, None),
    };

    keychain
      .sign(
        &target.path,
        entitlements_path.as_deref(),
        target.is_an_executable && settings.macos().hardened_runtime,
      )
      .map_err(Box::new)?;
  }

  Ok(())
}

pub fn notarize(
  keychain: &tauri_macos_sign::Keychain,
  app_bundle_path: PathBuf,
  credentials: &tauri_macos_sign::AppleNotarizationCredentials,
) -> crate::Result<()> {
  tauri_macos_sign::notarize(keychain, &app_bundle_path, credentials)
    .map_err(Box::new)
    .map_err(Into::into)
}

pub fn notarize_without_stapling(
  keychain: &tauri_macos_sign::Keychain,
  app_bundle_path: PathBuf,
  credentials: &tauri_macos_sign::AppleNotarizationCredentials,
) -> crate::Result<()> {
  tauri_macos_sign::notarize_without_stapling(keychain, &app_bundle_path, credentials)
    .map_err(Box::new)
    .map_err(Into::into)
}

pub fn notarize_auth() -> Result<tauri_macos_sign::AppleNotarizationCredentials, NotarizeAuthError>
{
  match (
    var_os("APPLE_ID"),
    var_os("APPLE_PASSWORD"),
    var_os("APPLE_TEAM_ID"),
  ) {
    (Some(apple_id), Some(password), Some(team_id)) => {
      Ok(tauri_macos_sign::AppleNotarizationCredentials::AppleId {
        apple_id,
        password,
        team_id,
      })
    }
    (Some(_apple_id), Some(_password), None) => Err(NotarizeAuthError::MissingTeamId),
    _ => {
      match (
        var_os("APPLE_API_KEY"),
        var_os("APPLE_API_ISSUER"),
        var("APPLE_API_KEY_PATH"),
      ) {
        (Some(key_id), Some(issuer), Ok(key_path)) => {
          Ok(tauri_macos_sign::AppleNotarizationCredentials::ApiKey {
            key_id,
            key: tauri_macos_sign::ApiKey::Path(key_path.into()),
            issuer,
          })
        }
        (Some(key_id), Some(issuer), Err(_)) => {
          let mut api_key_file_name = OsString::from("AuthKey_");
          api_key_file_name.push(&key_id);
          api_key_file_name.push(".p8");
          let mut key_path = None;

          let mut search_paths = vec!["./private_keys".into()];
          if let Some(home_dir) = dirs::home_dir() {
            search_paths.push(home_dir.join("private_keys"));
            search_paths.push(home_dir.join(".private_keys"));
            search_paths.push(home_dir.join(".appstoreconnect").join("private_keys"));
          }

          for folder in search_paths {
            if let Some(path) = find_api_key(folder, &api_key_file_name) {
              key_path = Some(path);
              break;
            }
          }

          if let Some(key_path) = key_path {
            Ok(tauri_macos_sign::AppleNotarizationCredentials::ApiKey {
              key_id,
              key: tauri_macos_sign::ApiKey::Path(key_path),
              issuer,
            })
          } else {
            Err(NotarizeAuthError::MissingApiKey {
              file_name: api_key_file_name.to_string_lossy().into_owned(),
            })
          }
        }
        _ => Err(NotarizeAuthError::MissingCredentials),
      }
    }
  }
}

fn find_api_key(folder: PathBuf, file_name: &OsString) -> Option<PathBuf> {
  let path = folder.join(file_name);
  if path.exists() { Some(path) } else { None }
}

#[cfg(test)]
mod tests {
  use super::*;
  fn parent(sandbox: bool) -> Entitlements {
    let mut p = plist::Dictionary::new();
    p.insert("com.apple.security.app-sandbox".into(), sandbox.into());
    p.insert("com.apple.security.network.client".into(), true.into());
    p.insert("com.apple.security.get-task-allow".into(), true.into());
    p.insert("com.apple.security.cs.allow-jit".into(), true.into());
    p.insert(
      "com.apple.application-identifier".into(),
      "TEST.example.app".into(),
    );
    Entitlements::Plist(p.into())
  }
  fn value(e: Option<Entitlements>) -> plist::Value {
    match e.unwrap() {
      Entitlements::Plist(v) => v,
      _ => panic!("expected inline entitlements"),
    }
  }
  #[test]
  fn sandboxed_cef_helpers_get_only_sandbox_and_inherit() {
    let p = parent(true);
    let v = value(target_entitlements(Some(&p), true).unwrap());
    let d = v.as_dictionary().unwrap();
    assert_eq!(d.len(), 2);
    assert_eq!(
      d.get("com.apple.security.app-sandbox")
        .and_then(plist::Value::as_boolean),
      Some(true)
    );
    assert_eq!(
      d.get("com.apple.security.inherit")
        .and_then(plist::Value::as_boolean),
      Some(true)
    );
    // Main remains unchanged, including its identity and non-inherited grants.
    assert_eq!(
      value(target_entitlements(Some(&p), false).unwrap())
        .as_dictionary()
        .unwrap()
        .len(),
      5
    );
  }
  #[test]
  fn ordinary_targets_and_non_sandbox_cef_keep_configured_entitlements() {
    for sandbox in [true, false] {
      let p = parent(sandbox);
      let Entitlements::Plist(original) = &p else {
        unreachable!()
      };
      assert_eq!(
        &value(target_entitlements(Some(&p), false).unwrap()),
        original
      );
      if !sandbox {
        assert_eq!(
          &value(target_entitlements(Some(&p), true).unwrap()),
          original
        );
      }
    }
    assert!(target_entitlements(None, true).unwrap().is_none());
    let p = Entitlements::Path("unread-for-ordinary-target.plist".into());
    assert!(matches!(
      target_entitlements(Some(&p), false).unwrap(),
      Some(Entitlements::Path(_))
    ));
  }
  #[test]
  fn sandbox_path_is_read_without_modifying_its_parent_file() {
    let file = tempfile::NamedTempFile::new().unwrap();
    let Entitlements::Plist(original) = parent(true) else {
      unreachable!()
    };
    original.to_file_xml(file.path()).unwrap();
    let before = std::fs::read(file.path()).unwrap();
    let derived =
      value(target_entitlements(Some(&Entitlements::Path(file.path().into())), true).unwrap());
    assert_eq!(derived.as_dictionary().unwrap().len(), 2);
    assert_eq!(std::fs::read(file.path()).unwrap(), before);
  }
  #[test]
  fn malformed_or_missing_helper_configuration_fails_closed() {
    assert!(
      target_entitlements(
        Some(&Entitlements::Path("missing-helper-test.plist".into())),
        true
      )
      .is_err()
    );
    assert!(
      target_entitlements(Some(&Entitlements::Plist("not-a-dictionary".into())), true).is_err()
    );
    let mut bad = plist::Dictionary::new();
    bad.insert("com.apple.security.app-sandbox".into(), "true".into());
    assert!(target_entitlements(Some(&Entitlements::Plist(bad.into())), true).is_err());
    let Entitlements::Plist(mut p) = parent(true) else {
      unreachable!()
    };
    p.as_dictionary_mut()
      .unwrap()
      .insert("com.apple.security.inherit".into(), true.into());
    assert!(target_entitlements(Some(&Entitlements::Plist(p)), true).is_err());
  }
}
