---
"tauri-cli": "patch:bug"
---

Preserve `--no-default-features` from `tauri build` through bundling, and allow it on `tauri bundle`, so runtime selection does not package a disabled default CEF runtime with a Wry application.
