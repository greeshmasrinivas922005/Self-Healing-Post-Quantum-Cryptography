# VaultIQ — Self-Healing Post-Quantum Secure File Vault

A local educational final-year prototype combining real file encryption, JDK-standardized post-quantum operations, a deliberately toy RSA/Shor lesson, controlled key rotation, and verifiable file recovery.

> **Prototype boundary:** This is a final-year engineering prototype, not production file-vault software, and it has not had an independent security review. Keep the default server on loopback. A separately gated remote lab mode is available only with HTTPS, mutual TLS, an allowlisted client IP, and a strong bearer token. The Shor page is a classical educational simulation using a preselected period for `N = 3233`; it is not a quantum computation or a real-world threat detector. The toy RSA demonstration triggers a controlled key rotation and re-protection exercise; it does not mean an RSA key encrypted the vault file.

## Requirements and launch

- Windows and a full JDK 24 or later (`java` and `javac` on `PATH`). The JDK must provide `ML-KEM` and `ML-DSA`.
- No external framework, package manager, or crypto dependency is required.
- Start `run.bat`, then open the local URL printed by the Java server. The server binds to loopback only and checks nearby ports when 8090 is busy.
- Open the printed server URL for the VaultIQ dashboard. File upload, cryptographic process, PQC, monitor, attack, healing, recovery, audit, and assistant views are separately navigable. The preserved message lab is available at `index.html`; RSA and Shor teaching demonstrations remain available separately.

On first use, create a username and password of at least 12 characters. The password is stored only as a salted PBKDF2-HMAC-SHA-256 verifier and also encrypts the PQC key bundle. Sign in again after a server restart; browser sessions are revoked when the process stops, on sign-out, and during validated self-healing. Changing the password rewraps the key bundle and updates the account verifier. There is no password reset or recovery. Account data is stored in `data/vault/account.properties`; encrypted keys, file packages, verified backups, and audit data are stored in `data/vault/keys.bundle`, `data/vault/records/`, `data/vault/backups/`, and `data/vault/audit.log`. Do not delete these vault files unless you intend to permanently lose the demo data.

## File-protection design

1. The browser displays filename, browser-reported MIME type, size, and a SHA-256 digest. Java independently calculates SHA-256 and the UI compares both values.
2. Java generates a random 256-bit AES file key and a unique 96-bit nonce. `AES/GCM/NoPadding` encrypts the file; its 128-bit tag is retained with the ciphertext.
3. Java encapsulates with the active JDK `ML-KEM-768` public key. HKDF-SHA-256 derives a wrapping key from that shared secret; AES-GCM wraps the per-file AES key. KEM never encrypts bulk file bytes.
4. Canonical, length-prefixed UTF-8 metadata (including file SHA-256, version, original name/type/size, algorithm labels, and timestamp) is signed by JDK `ML-DSA-65`.
5. Storage contains ciphertext, nonce, wrapped file key, KEM encapsulation, signed metadata, and signature. Plaintext is not written to disk. On recovery, Java verifies the ML-DSA signature, unwraps the file key, checks the AES-GCM tag, and checks recovered length and SHA-256 before returning a download.

The passphrase-encrypted key bundle uses PBKDF2-HMAC-SHA-256 with 600,000 iterations and AES-GCM. This is a demonstration key store, not a hardware-backed key-management system.

## Controlled self-healing flow

The existing textbook RSA page and Shor page are preserved as educational modules. The Shor page uses fixed `N = 3233`, factors `61 × 53`, and preselected `r = 260`; the factor calculations are classical arithmetic. In the local flow, the Shor page submits one-use-session evidence to the loopback backend. The separate Computer B client uses a real HTTPS/TLS 1.3 connection with mutual TLS and a one-use bearer token. Both paths accept only the fixed, validated project test values.

A validated event advances the persisted state, invalidates the initial one-use RSA-test session (the vault never uses RSA to encrypt files), generates a new ML-KEM-768 and ML-DSA-65 version, decrypts and verifies every old file, re-encrypts each under a new random AES key and KEM envelope, re-signs canonical metadata, verifies the migrated version, switches active file pointers, removes the old PQC private-key version, and marks `PQC_ACTIVE`. A repeat demonstration gets a distinct one-use session, repeats only the same toy factorization, and logs separately that the prior RSA-test session is invalid and the prior ML-KEM/ML-DSA vault key version was retired after verified migration. This does not claim PQC is unbreakable.

The controlled tamper action flips a bit in stored ciphertext, checks that AES-GCM rejects it, restores the encrypted backup, then verifies the signature, GCM tag, and file hash.

## Existing educational pages

- RSA: `rsa.html` and `js/rsa.js` retain their small fixed-prime arithmetic, character-by-character textbook RSA demonstration, and calculations. This is not a secure RSA implementation.
- Shor: `quantum.html` and `js/quantum.js` retain the fixed small-number, preselected-period simulation. Vault sessions alone connect accepted evidence to vault recovery.
- PQC: `pqc.html` calls the Java backend to run actual ML-KEM-768 encapsulation/decapsulation and ML-DSA-65 signing/verification with active vault keys. The browser displays public artifacts and fingerprints, never secret key or shared-secret bytes.
- Message lab: `index.html` and `/api/protect`, `/api/recover`, and `/api/benchmark` remain separate from file-vault records.

`frontend/` is the maintained and served source tree. `backend/web/` is a legacy static snapshot and is not served by the Java server. The vault controllers (`vault.js`, `files.js`, `threat.js`, `keys.js`, `audit.js`, `workflow.js`, and `assistant.js`) share `vault-common.js` for navigation and account sign-in. Uploads after migration use the currently active key version.

Backend operation measurements use `System.nanoTime()` and are returned with an upload result and appended as performance audit events for SHA-256, AES-GCM encryption, ML-KEM key wrapping, ML-DSA signing, total upload, migration, and recovery. Durations are measurements of this run and machine, not fixed benchmark claims.

## VaultAI and security views

VaultAI is an AI-assisted, security-context-grounded chat workspace at `assistant.html`, backed by `/api/vault/security-context` and `/api/vault/assistant`. It supports multi-turn context for the current browser conversation, project and cryptography explanations, persisted event summaries, live posture and integrity indicators, and next-step recommendations. Chat history is held only in browser memory and sent with each request; it is not persisted in the vault. The AI-generated recommendations are advisory only: VaultAI cannot trigger recovery, key rotation, upload, or deletion. Without a provider key, a deterministic local knowledge fallback answers supported security questions.

To enable broad provider-backed chat, set `OPENAI_API_KEY` in the environment of the Java server before launching `run.bat`; optionally set `VAULTAI_MODEL` to a model available to your account (default: `gpt-5.6`). For example, in PowerShell use `$env:OPENAI_API_KEY = "your-key"; .\run.bat`. Never send the key in chat or commit it to source control. The key remains server-side. The provider receives the question, bounded recent conversation, and allowlisted sanitized security metadata (state, key version, per-file status without filename/hash, and recent event summaries); it does not receive vault file bytes, filenames, hashes, passwords, or private keys as automatic context. Text a user chooses to include in a prompt is sent to the provider when provider mode is enabled. Provider errors are reported in the assistant UI and fall back to local project-focused answers. Without the key, the local fallback is limited to project and security topics; the provider-backed assistant supports broader open-ended questions and tasks, but cannot guarantee a correct answer to everything. Security Monitor, Attack Lab, Self-Healing, and Recovery views remain backend-driven and do not create demonstration events. The separate Remote Attack Demo view guides Computer A and Computer B through the authorized network test and displays persisted connection evidence and self-healing milestones. Risk indicators report observed backend state; they are not an ML intrusion detector or production security rating.

VaultIQ now has first-run account registration and subsequent login. Account passwords are verified with salted PBKDF2-HMAC-SHA-256 and also encrypt the local PQC key bundle. Authenticated browser sessions use random HttpOnly, SameSite cookies, expire after one hour, are revoked on logout, and rotate after a validated threat event. The account is single-user and local to the configured vault directory.

## Two-computer authorized lab

The default `run.bat` mode is loopback-only. To use Computer B, provision short-lived TLS 1.3 credentials on Computer A using `tools\create-remote-lab-certs.ps1 -ServerIp <Computer-A-private-IP> -OutputDirectory <private-output-directory>`. It creates a server PKCS#12 keystore, a server truststore containing the client certificate, a client PKCS#12 keystore, a client truststore containing the server certificate, and a random bearer token. Keep that output directory private; transfer only the client keystore, client truststore, and token to Computer B using a private channel. The script uses self-signed certificates for this isolated demonstration, not a reusable production CA. Use a private lab network.

- Computer A: `VAULT_LAB_TOKEN` (at least 32 random characters), `VAULT_LAB_CLIENT_ADDRESS` (Computer B's exact IP), `VAULT_TLS_KEYSTORE`, `VAULT_TLS_KEYSTORE_PASSWORD`, `VAULT_TLS_TRUSTSTORE`, and `VAULT_TLS_TRUSTSTORE_PASSWORD`.
- Computer B: `VAULT_TARGET_HOST`, `VAULT_TARGET_PORT`, the same `VAULT_LAB_TOKEN`, `VAULT_TLS_CLIENT_KEYSTORE`, `VAULT_TLS_CLIENT_KEYSTORE_PASSWORD`, `VAULT_TLS_TRUSTSTORE`, and `VAULT_TLS_TRUSTSTORE_PASSWORD`.

On Computer A, allow the chosen TCP port for Java on the **Private** network profile only, then run `powershell -ExecutionPolicy Bypass -File tools\run-authorized-lab.ps1 -Role server -PrivateAddress <Computer-A-private-IP> -AllowedClientAddress <Computer-B-private-IP>`. To use a fresh demo vault and leave `data\vault` untouched, add `-VaultRoot data/vault-remote-demo`. Enter the prompted certificate paths and secrets, open the printed HTTPS URL using Computer A's private IP in a browser on Computer A, trust the lab server certificate for this isolated demo, sign in to the vault, and upload a harmless sample file. Copy `backend\AttackLabClient.java`, `tools\run-authorized-lab.ps1`, and the client keystore/truststore to Computer B while keeping the same relative `backend` and `tools` folders. On Computer B, run `powershell -ExecutionPolicy Bypass -File tools\run-authorized-lab.ps1 -Role client -ServerAddress <Computer-A-private-IP> -Port <printed-port> -Purpose initial`, then run it again with `-Purpose repeat` after migration. The helper prompts for secrets without echoing them and clears its process environment after each client run. The client checks the fixed project challenge and submits evidence only to `/api/lab/*`. Remote vault pages require an authenticated browser session; sign in again after healing because sessions are revoked. Do not reuse these lab certificates or expose the test endpoint to the Internet. The recorded network evidence contains the peer source IP, destination address and port, fixed project target, route, timestamp, and result.

## API surface

- `GET /api/vault/status`
- `GET /api/vault/security-context`
- `POST /api/vault/assistant`
- `POST /api/vault/register` and `POST /api/vault/login`
- `POST /api/vault/logout`
- `POST /api/vault/pqc-self-test`
- `POST /api/vault/upload` (`multipart/form-data`, maximum 16 MiB)
- `GET /api/vault/files` and `GET /api/vault/files/{id}`
- `GET /api/vault/files/{id}/download`
- `DELETE /api/vault/files/{id}`
- `POST /api/vault/files/{id}/tamper`
- `POST /api/vault/attack-session`, `POST /api/vault/threat`, and `POST /api/vault/repeat-attack`
- `GET /api/vault/audit`

## Tests

Run the full acceptance test from PowerShell with `node tests\\vault-acceptance.mjs`. It compiles and starts the Java server using a temporary vault directory, then tests account registration/login, browser-session enforcement and logout, real ML-KEM/ML-DSA self-tests, multipart upload, metadata signature, verified download, tamper restoration, one-use threat session, key migration, session revocation, repeat attack, password rewrap, file deletion, persistence, and audit ordering. Its temporary data is removed afterward. Node.js 24 or later is required for this test script.

With the server already running, `tests\\smoke-test.ps1` checks the preserved message API. If the port is not 8090, pass the printed URL with `-BaseUrl`.

## Report evidence

Record the JDK/build, machine, file sizes/types, repeated measurements, operation timings, ciphertext/encapsulation/signature sizes, state transitions, error cases, and audit evidence. In the report, distinguish the actual JDK cryptographic operations from the simulated toy RSA/Shor demonstration and disclose the local-only/passphrase/key-store limitations.
