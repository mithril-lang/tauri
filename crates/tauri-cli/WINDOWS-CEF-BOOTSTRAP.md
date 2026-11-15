# Explicit Windows CEF bootstrap profile

This experimental profile packages the same application as a CEF client DLL.
The matching CEF distribution's `bootstrap.exe` loads a same-named DLL and
provides the checked browser/subprocess sandbox broker to `RunWinMain`.
There is no WebView2 or unsandboxed fallback.

Set `bundle.cef.embed` and `bundle.cef.windowsBootstrap` to `true`. Use an
explicit MSVC target and an isolated, fresh `CARGO_TARGET_DIR` per candidate.
The application needs an explicit `[lib]` with `crate-type = ["cdylib"]`
(additional crate types are allowed). Set a library name different from the
main executable base name so the original Cargo DLL is never mutated.
Export the shared application entry:

```rust,ignore
#[cfg(target_os = "windows")]
#[tauri::cef_entry_point(windows_bootstrap)]
pub fn windows_main() {
    run(); // The existing shared application, not a second implementation.
}
```

`tauri build --target x86_64-pc-windows-msvc` builds only that library, checks
its architecture and executable `RunWinMain` export, and stages the bootstrap
EXE/client DLL pair. Both files use the configured main binary's base name.
Existing output files are refused rather than overwritten; retain partial
candidates for diagnosis and start the next attempt in a new target directory.
This profile currently rejects `tauri dev` and alternative Cargo target selectors.

Before bundling, the pair must still match the original Cargo DLL and CEF
bootstrap byte for byte. Externally modified or pre-signed stages cannot be
rebundled through this profile. The bundler adds the client DLL at the install
root without changing existing resource destinations. Tauri bundle metadata
is patched in the client DLL; configured signing runs after that patch.
The bootstrap is not patched as though it contained Rust/Tauri metadata.
Normal errors and unwinds restore the staged DLL via atomic replacement and
full content read-back. Process abort/kill cannot run restoration. An interrupted
or failed restoration retains a named recovery copy and an in-progress marker;
further bundling is refused pending owner reconciliation. Preserve the entire
candidate on unknown outcomes; do not delete its marker to retry automatically.
This is not a power-loss or OS-level crash qualification.

Component tests and cross-target type checking do not qualify the CEF SDK ABI,
Windows loader, process sandbox, installer, signing or Microsoft Store release.
Those require an exact-source native Windows lane and an independent result
collector. A consuming application's dependency pin stays unchanged until that
qualification is complete. Never disable its Required sandbox policy to make
this candidate launch.
