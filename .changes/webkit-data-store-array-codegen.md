---
"tauri-utils": "patch:bug"
---

Generate a fixed byte array for `WindowConfig.dataStoreIdentifier`, matching its `Option<[u8; 16]>` type, so declarative WebKit datastore isolation compiles through `generate_context!`.
