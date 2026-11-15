---
"tauri-bundler": "patch:bug"
---

Sign spawned CEF helper apps with App Sandbox inheritance entitlements when the main app enables App Sandbox, instead of copying the main app’s identity and grants onto the helpers. Preserve configured entitlements for other targets and non-sandboxed CEF applications.
