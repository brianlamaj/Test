# pwman (Windows C++20 Password Manager CLI)

`pwman` is a single-file vault password manager for Windows, targeting Visual Studio 2026 CMake workflows.

## Security design

- KDF: Argon2id via `crypto_pwhash` (libsodium)
- Encryption: `crypto_aead_xchacha20poly1305_ietf_*`
- Vault format:
  - Plaintext header: `magic`, `version`, `opslimit`, `memlimit`, `alg`, `salt`, `nonce`
  - Ciphertext payload: JSON entries
  - Entire header is supplied as AEAD AAD, so header tampering is detected

## Dependencies

Installed via `vcpkg.json`:

- libsodium
- nlohmann-json

## Build (Visual Studio 2026 + CMake)

1. Ensure `VCPKG_ROOT` is set and dependencies are installed for `x64-windows`.
2. Open folder in Visual Studio and select configure preset `vs2026-vcpkg`.
3. Build preset `build`.
4. Run tests preset `test`.

CLI binary: `pwman`.

## CLI usage

```text
pwman <vault-file> init <master_password>
pwman <vault-file> add <master_password> <name> <username> <password> [notes]
pwman <vault-file> get <master_password> <name>
pwman <vault-file> list <master_password>
pwman <vault-file> update <master_password> <name> [--username v] [--password v] [--notes v]
pwman <vault-file> remove <master_password> <name>
pwman <vault-file> gen [length]
```

## Tests

`crypto_tests` validates:
- encryption/decryption round-trip
- tamper detection (ciphertext byte flip should fail authentication)
