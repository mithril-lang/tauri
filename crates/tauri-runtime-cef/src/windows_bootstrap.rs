// Copyright 2019-2024 Tauri Programme within The Commons Conservancy
// SPDX-License-Identifier: Apache-2.0
// SPDX-License-Identifier: MIT

//! Broker custody for a CEF bootstrap-hosted Windows client DLL.
//!
//! CEF owns the pointer. It is neither serialized nor accepted from a command
//! line, environment variable or renderer. Only the bootstrap entry on the
//! current thread may lend it to CEF, for the duration of that entry.

use std::{
  cell::Cell,
  ffi::c_void,
  sync::atomic::{AtomicBool, Ordering},
};

// CEF 154 include/cef_version_info.h, including the size-gated installer fields.
// cef-rs does not currently expose this bootstrap-only structure. Keep this
// private layout paired with the pinned CEF header; do not infer compatibility
// from a non-null sandbox pointer alone.
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct VersionInfo {
  size: usize,
  cef_major: i32,
  cef_minor: i32,
  cef_patch: i32,
  cef_commit: i32,
  chrome_major: i32,
  chrome_minor: i32,
  chrome_build: i32,
  chrome_patch: i32,
  sandbox_hash: [u8; 17],
  libcef_path: *const u16,
  libcef_is_bundled: i32,
  libcef_version_full: *const std::ffi::c_char,
  installer_error_code: i32,
  installer_error_message: *const std::ffi::c_char,
}

impl VersionInfo {
  fn compatible_with(&self, library: &Self) -> bool {
    self.size >= std::mem::size_of::<Self>()
      && library.size >= std::mem::size_of::<Self>()
      && self.installer_error_code == 0
      && library.installer_error_code == 0
      && self.sandbox_hash[16] == 0
      && self.sandbox_hash[..16].iter().all(u8::is_ascii_hexdigit)
      && self.sandbox_hash == library.sandbox_hash
      && [
        self.cef_major,
        self.cef_minor,
        self.cef_patch,
        self.cef_commit,
        self.chrome_major,
        self.chrome_minor,
        self.chrome_build,
        self.chrome_patch,
      ] == [
        library.cef_major,
        library.cef_minor,
        library.cef_patch,
        library.cef_commit,
        library.chrome_major,
        library.chrome_minor,
        library.chrome_build,
        library.chrome_patch,
      ]
  }
}

thread_local! {
  static BROKER: Cell<*mut c_void> = const { Cell::new(std::ptr::null_mut()) };
}

pub(crate) fn sandbox_info() -> *mut c_void {
  BROKER.with(Cell::get)
}

struct BrokerScope;
impl BrokerScope {
  fn enter(pointer: *mut c_void, entered: &AtomicBool) -> Option<Self> {
    if pointer.is_null()
      || entered
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
      return None;
    }
    BROKER.with(|broker| broker.set(pointer));
    Some(Self)
  }
}
impl Drop for BrokerScope {
  fn drop(&mut self) {
    // Never destroy CEF's object: bootstrap.exe retains ownership.
    BROKER.with(|broker| broker.set(std::ptr::null_mut()));
  }
}

/// Runs a client DLL entry called by CEF's matching Windows bootstrap.
///
/// A standalone executable still has no broker and Required still refuses it.
/// This port alone does not build/package the client DLL or qualify the Windows
/// process sandbox. Use the entry macro and the matching distribution bootstrap.
///
/// # Safety
/// The caller must be CEF's process entry, on its original thread, before any
/// application or CEF initialization. `sandbox_info` must be the live opaque
/// object owned by that bootstrap, valid until this function returns.
/// `version_info` must point to CEF's readable, aligned, size-tagged version
/// object. Neither pointer may be fabricated or reused after bootstrap exits.
#[cfg(windows)]
pub unsafe fn run_windows_bootstrap(
  sandbox_info: *mut c_void,
  version_info: *const c_void,
  entry: impl FnOnce(),
) -> i32 {
  const REFUSED: i32 = 78;
  static ENTERED: AtomicBool = AtomicBool::new(false);
  if sandbox_info.is_null()
    || version_info.is_null()
    || (version_info as usize) % std::mem::align_of::<VersionInfo>() != 0
  {
    return REFUSED;
  }
  // Read only the size before borrowing the complete, version-gated layout.
  let size = unsafe { version_info.cast::<usize>().read() };
  if size < std::mem::size_of::<VersionInfo>() {
    return REFUSED;
  }
  let bootstrap = unsafe { &*version_info.cast::<VersionInfo>() };
  let mut library = VersionInfo {
    size: std::mem::size_of::<VersionInfo>(),
    ..Default::default()
  };
  unsafe extern "C" {
    fn cef_version_info_all(info: *mut VersionInfo);
  }
  unsafe { cef_version_info_all(&mut library) };
  if !bootstrap.compatible_with(&library) {
    return REFUSED;
  }
  let Some(_scope) = BrokerScope::enter(sandbox_info, &ENTERED) else {
    return REFUSED;
  };
  // A Rust unwind must never cross the exported C ABI. Abort remains fatal.
  match std::panic::catch_unwind(std::panic::AssertUnwindSafe(entry)) {
    Ok(()) => 0,
    Err(_) => REFUSED,
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  fn version() -> VersionInfo {
    VersionInfo {
      size: std::mem::size_of::<VersionInfo>(),
      cef_major: 154,
      cef_patch: 34,
      cef_commit: 1,
      chrome_major: 154,
      chrome_build: 8037,
      chrome_patch: 98,
      sandbox_hash: *b"0123456789abcdef\0",
      ..Default::default()
    }
  }

  #[test]
  fn version_pair_requires_complete_matching_bootstrap_and_library() {
    let good = version();
    assert!(good.compatible_with(&good));
    let mut bad = good;
    bad.chrome_patch += 1;
    assert!(!bad.compatible_with(&good));
    bad = good;
    bad.sandbox_hash[0] = b'f';
    assert!(!bad.compatible_with(&good));
    bad = good;
    bad.size -= 1;
    assert!(!bad.compatible_with(&good));
    assert!(!good.compatible_with(&bad));
    bad = good;
    bad.installer_error_code = 1;
    assert!(!bad.compatible_with(&good));
    assert!(!good.compatible_with(&bad));
  }

  #[test]
  fn missing_or_nonterminated_sandbox_hash_is_not_compatibility() {
    for hash in [[0; 17], *b"0123456789abcdeg\0", *b"0123456789abcdefX"] {
      let bad = VersionInfo {
        sandbox_hash: hash,
        ..version()
      };
      assert!(!bad.compatible_with(&bad));
    }
  }

  #[test]
  fn broker_is_thread_bound_cleared_on_return_and_never_reentered() {
    let entered = AtomicBool::new(false);
    assert!(BrokerScope::enter(std::ptr::null_mut(), &entered).is_none());
    let pointer = std::ptr::NonNull::<u8>::dangling().as_ptr().cast();
    {
      let _scope = BrokerScope::enter(pointer, &entered).unwrap();
      assert_eq!(sandbox_info(), pointer);
      assert!(std::thread::spawn(|| sandbox_info().is_null())
        .join()
        .unwrap());
      assert!(BrokerScope::enter(pointer, &entered).is_none());
    }
    assert!(sandbox_info().is_null());
    assert!(BrokerScope::enter(pointer, &entered).is_none());
  }

  #[test]
  fn unwinding_clears_the_borrowed_broker_without_reopening_entry() {
    let entered = AtomicBool::new(false);
    let pointer = std::ptr::NonNull::<u8>::dangling().as_ptr().cast();
    let result = std::panic::catch_unwind(|| {
      let _scope = BrokerScope::enter(pointer, &entered).unwrap();
      panic!("fixture");
    });
    assert!(result.is_err());
    assert!(sandbox_info().is_null());
    assert!(entered.load(Ordering::Acquire));
  }
}
