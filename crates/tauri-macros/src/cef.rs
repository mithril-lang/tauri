// Copyright 2019-2024 Tauri Programme within The Commons Conservancy
// SPDX-License-Identifier: Apache-2.0
// SPDX-License-Identifier: MIT

use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, ItemFn};

pub fn entry_point(attributes: TokenStream, item: TokenStream) -> TokenStream {
  let function = parse_macro_input!(item as ItemFn);
  match expand(attributes.into(), function) {
    Ok(tokens) => tokens.into(),
    Err(error) => error.to_compile_error().into(),
  }
}

fn expand(
  attributes: proc_macro2::TokenStream,
  mut function: ItemFn,
) -> syn::Result<proc_macro2::TokenStream> {
  let bootstrap = if attributes.is_empty() {
    false
  } else {
    let attribute: syn::Ident = syn::parse2(attributes)?;
    if attribute != "windows_bootstrap" {
      return Err(syn::Error::new_spanned(
        attribute,
        "expected windows_bootstrap or no arguments",
      ));
    }
    true
  };
  if bootstrap
    && (!function.sig.inputs.is_empty()
      || function.sig.output != syn::ReturnType::Default
      || function.sig.asyncness.is_some()
      || function.sig.unsafety.is_some()
      || function.sig.constness.is_some()
      || function.sig.abi.is_some()
      || !function.sig.generics.params.is_empty())
  {
    return Err(syn::Error::new_spanned(
      &function.sig,
      "windows_bootstrap requires a synchronous safe non-generic fn() with no return value",
    ));
  }
  let original_block = function.block.clone();

  let has_return_type = function.sig.output != syn::ReturnType::Default;
  let process_check = if has_return_type {
    quote! {
      // Check if this is the browser process
      let is_browser_process = !std::env::args()
        .any(|arg| arg.starts_with("--type="));

      if !is_browser_process {
        ::tauri_runtime_cef::run_cef_helper_process();
        return Default::default();
      }
    }
  } else {
    quote! {
      // Check if this is the browser process
      let is_browser_process = !std::env::args()
        .any(|arg| arg.starts_with("--type="));

      if !is_browser_process {
        ::tauri_runtime_cef::run_cef_helper_process();
        return;
      }
    }
  };

  function.block = syn::parse2(quote! {
    {
      #process_check
      #original_block
    }
  })
  .expect("Failed to parse block");

  let windows_entry = if bootstrap {
    let name = &function.sig.ident;
    quote! {
      // CEF 154 cef_sandbox_win.h: C ABI, including the fifth version argument.
      // Export from the client cdylib, NOT from a replacement bootstrap executable.
      #[cfg(target_os = "windows")]
      #[doc(hidden)]
      #[allow(non_snake_case)]
      #[unsafe(no_mangle)]
      pub unsafe extern "C" fn RunWinMain(
        _instance: *mut ::std::ffi::c_void,
        _command_line: *mut u16,
        _command_show: i32,
        sandbox_info: *mut ::std::ffi::c_void,
        version_info: *const ::std::ffi::c_void,
      ) -> i32 {
        unsafe {
          ::tauri_runtime_cef::run_windows_bootstrap(sandbox_info, version_info, || #name())
        }
      }
    }
  } else {
    quote! {}
  };
  Ok(quote!(#function #windows_entry))
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn bootstrap_export_uses_the_five_argument_c_abi() {
    let output = expand(
      quote!(windows_bootstrap),
      syn::parse_quote!(
        pub fn run() {}
      ),
    )
    .unwrap();
    let file: syn::File = syn::parse2(output).unwrap();
    assert_eq!(file.items.len(), 2);
    let syn::Item::Fn(entry) = &file.items[1] else {
      panic!("missing entry")
    };
    assert_eq!(entry.sig.ident, "RunWinMain");
    assert_eq!(entry.sig.inputs.len(), 5);
    assert!(entry.sig.unsafety.is_some());
    assert_eq!(
      entry
        .sig
        .abi
        .as_ref()
        .unwrap()
        .name
        .as_ref()
        .unwrap()
        .value(),
      "C"
    );
  }

  #[test]
  fn ordinary_entry_does_not_export_a_windows_dll_callback() {
    let file: syn::File = syn::parse2(
      expand(
        quote!(),
        syn::parse_quote!(
          fn main() -> Result<(), ()> {
            Ok(())
          }
        ),
      )
      .unwrap(),
    )
    .unwrap();
    assert_eq!(file.items.len(), 1);
  }

  #[test]
  fn bootstrap_rejects_callbacks_with_an_incompatible_signature() {
    for function in [
      syn::parse_quote!(
        fn run(x: u32) {}
      ),
      syn::parse_quote!(
        async fn run() {}
      ),
      syn::parse_quote!(
        unsafe fn run() {}
      ),
      syn::parse_quote!(
        fn run<T>() {}
      ),
      syn::parse_quote!(
        fn run() -> i32 {
          0
        }
      ),
    ] {
      assert!(expand(quote!(windows_bootstrap), function).is_err());
    }
    assert!(expand(
      quote!(unknown),
      syn::parse_quote!(
        fn main() {}
      )
    )
    .is_err());
  }
}
