# VaultIQ: Self-Healing Post-Quantum Secure File Vault

## Abstract

The continuing development of quantum computing has encouraged researchers and standards organizations to prepare for possible future attacks against public-key cryptography. At the same time, practical file-security systems must address more than the choice of encryption algorithm: they must protect encryption keys, detect changes to stored data, verify files before recovery, and provide a safe way to replace cryptographic keys. This project presents VaultIQ, an educational prototype that demonstrates these ideas in a local file-vault application.

VaultIQ uses a hybrid file-protection design. The Java backend encrypts each uploaded file with AES-256-GCM using a fresh per-file symmetric key and nonce. It uses the standardized ML-KEM-768 key-encapsulation mechanism to establish secret material used to wrap the file key, and ML-DSA-65 to sign canonical metadata associated with the protected file. During recovery, the backend verifies the metadata signature, unwraps the file key, checks the GCM authentication tag, and confirms the recovered file length and SHA-256 digest before returning the file.

The prototype also demonstrates a controlled self-healing workflow. After the backend accepts a fixed educational RSA test event, it creates a new post-quantum key version, verifies and migrates protected records, re-signs metadata, verifies the migrated records, and retires the prior PQC key version. An optional two-computer lab uses HTTPS, mutual TLS, an allowlisted client address, and a bearer token. The RSA/Shor lesson uses a tiny fixed modulus, a preselected period, and classical arithmetic; it is not a quantum computation, a real-world attack, or an intrusion-detection system.

VaultIQ is intended for education and demonstration. It has not received an independent security review and should not be used to protect production or highly sensitive data. The project shows how current post-quantum standards can be incorporated into a key-wrapping, file-encryption, integrity-checking, and migration workflow while making the limits of the demonstration explicit.

## 1. Introduction

### 1.1 Background

Digital information is stored and transferred in many forms, including documents, images, software, research data, and business records. Encryption helps prevent unauthorized users from reading that information. Integrity checks and digital signatures help detect whether protected data or its associated metadata has changed. A complete file-protection design therefore requires several coordinated mechanisms rather than a single encryption operation.

Many established public-key systems depend on mathematical problems such as integer factorization or discrete logarithms. Peter Shor demonstrated that a sufficiently capable quantum computer could solve these problems much more efficiently than known classical algorithms.[1] This result has motivated work on post-quantum cryptography: cryptographic algorithms intended to remain secure against known classical and quantum attacks.

In August 2024, the National Institute of Standards and Technology (NIST) published its first post-quantum cryptography standards, including FIPS 203 for ML-KEM and FIPS 204 for ML-DSA.[2][3] ML-KEM is used to establish shared secret material; ML-DSA is used to generate and verify digital signatures. These algorithms do not replace every part of a file-encryption system. Bulk file bytes are generally encrypted using symmetric cryptography, while public-key operations protect or authenticate the keys and metadata.

### 1.2 Project overview

VaultIQ is a Java-backed educational file vault with a browser interface. It combines symmetric file encryption, post-quantum key encapsulation, metadata signatures, verified recovery, event recording, and a controlled key-migration demonstration. Separate pages explain cryptographic processing, file status, the controlled RSA/Shor lesson, PQC operations, self-healing milestones, audit records, and VaultAI.

The project has two different learning paths. The local path uses the same browser and Java backend. The optional remote path uses Computer B as a client and Computer A as the host. In the remote path, TLS 1.3 mutual authentication, an allowlisted client IP, and a one-use bearer token restrict access to the configured lab. The remote exercise is limited to fixed project-owned test evidence.

### 1.3 Project scope

The project demonstrates a defined set of cryptographic and operational concepts. It is not a general-purpose endpoint-protection product, cloud file-sharing service, production key-management service, or real quantum computer. The small RSA exercise is used to demonstrate the relationship between factoring and a controlled key rotation. It must not be represented as a real quantum attack or as proof that a real attacker was detected.

## 2. Problem statement

An educational file-encryption system that only shows ciphertext does not demonstrate whether the encryption key is protected, whether file metadata can be trusted, or whether recovery detects tampering. Likewise, rotating a key is not sufficient if stored files are not migrated and verified before the prior key is retired. These details are central to explaining how file confidentiality, integrity, recovery, and key lifecycle management work together.

The project addresses the following problem: how can a small local prototype demonstrate file encryption with a post-quantum key-establishment algorithm and signature algorithm, verify a file before recovery, and show a controlled key-version migration without misrepresenting a simulated quantum threat as a real one?

The problem is approached through a hybrid cryptographic design, backend-controlled validation, event-backed workflow views, and explicit educational boundaries. The project focuses on demonstrating a sequence of operations and recording their outcomes. It does not claim to solve production deployment concerns such as enterprise identity management, hardware-backed keys, independent monitoring, regulatory certification, or comprehensive security testing.

### 2.1 Key questions addressed

- How can large file data be encrypted efficiently while public-key cryptography protects the file key?
- How can the system detect changes to ciphertext and signed metadata?
- How can recovered files be checked before being returned to the user?
- What sequence is required to migrate files to a new key version safely?
- How can a remote lab client be authenticated and restricted to a fixed demonstration?
- How should a teaching interface communicate the difference between a classical simulation and a quantum computation?

## 3. Objectives

### 3.1 Primary objective

To design and implement an educational secure-file-vault prototype that combines AES-GCM encryption with standardized post-quantum key encapsulation and digital signatures, and demonstrates verified key rotation and file migration.

### 3.2 Specific objectives

1. **Protect file confidentiality.** Encrypt uploaded file bytes with AES-256-GCM using a randomly generated per-file key and unique nonce.
2. **Protect the file key.** Use ML-KEM-768 to establish secret material from which a wrapping key is derived, then use that wrapping key to protect the per-file AES key.
3. **Protect metadata integrity.** Construct canonical metadata and sign it using ML-DSA-65 so changes can be detected during later checks.
4. **Verify recovery.** Require valid signature, successful key unwrapping, a valid GCM tag, correct recovered length, and a matching SHA-256 digest before returning a file.
5. **Demonstrate key lifecycle management.** On accepted fixed test evidence, create a new key version, migrate and verify stored records, update active protection, and retire the prior PQC version.
6. **Record reviewable evidence.** Store events describing relevant file, key, test, and migration operations so the user can inspect the workflow.
7. **Demonstrate an authenticated remote lab.** Provide an optional two-computer test using TLS, mutual certificate authentication, source-address allowlisting, and a bearer token.
8. **Teach limitations responsibly.** Label the RSA/Shor exercise as a fixed toy example using classical arithmetic rather than a real quantum attack.
9. **Provide a clear interface.** Present file status, cryptographic operations, controlled tests, and recorded results in separate views.

### 3.3 Functional requirements

The functional requirements describe what a user can do and what the backend must perform.

- **FR-1: Account access.** A user can register or sign in before accessing protected vault operations. The backend checks credentials and creates a browser session.
- **FR-2: File upload.** A signed-in user can select a file within the configured upload limit and submit it to the backend.
- **FR-3: File protection.** The backend calculates its own digest, encrypts the file, wraps the file key, signs canonical metadata, and stores a protected record.
- **FR-4: File listing and inspection.** The user can view stored records and selected non-secret cryptographic metadata.
- **FR-5: Verified recovery.** A file is returned only after the configured signature, key-unwrapping, GCM authentication, length, and digest checks pass.
- **FR-6: Fixed local test.** The user can start an educational test session limited to project-owned values and submit the expected evidence to the backend.
- **FR-7: Remote authorized test.** When remote mode has been explicitly configured, a lab client can connect only with the required TLS client identity, source IP, and token.
- **FR-8: Key migration.** Validated test evidence can initiate the documented new-key migration and record its lifecycle events.
- **FR-9: Audit review.** The user can view persisted events and refresh the current event list.
- **FR-10: Assistant.** An authenticated user can submit a text question to VaultAI and receive an answer from the configured provider or the local fallback.

### 3.4 Non-functional requirements

- **Confidentiality:** protected file bytes should be stored as ciphertext; secret key material should not be exposed in ordinary browser views.
- **Integrity:** file payloads and signed metadata should be checked before recovery or migration is accepted.
- **Authentication:** sensitive vault API operations should require an authenticated browser session. The remote lab adds client-certificate, IP, and token checks.
- **Usability:** the browser should make operation stages, current state, and errors understandable to a student presenting the system.
- **Portability:** the source is intended for a Windows/JDK demonstration environment and uses standard web technologies.
- **Auditability:** important state transitions should be recorded so they can be reviewed after the operation.
- **Maintainability:** the browser, server, cryptographic service, and persistence responsibilities should be separable in the project structure.
- **Performance:** the design should measure operation times instead of presenting expected timings as guarantees.
- **Scope control:** all attack-related teaching paths should remain fixed-target educational demonstrations.

These requirements are project design goals, not a formal certification checklist. Their fulfillment should be assessed with repeatable tests and an independent security review before any real deployment.

## 4. Literature review

### 4.1 Quantum factoring and public-key cryptography

Shor’s paper on quantum computation describes polynomial-time quantum algorithms for integer factorization and discrete logarithms.[1] The result is important because factoring and discrete-logarithm assumptions underpin several widely used public-key cryptographic systems. Shor’s work is theoretical groundwork; it does not imply that a current laptop or the VaultIQ prototype can factor real-world RSA moduli with a quantum computer.

VaultIQ includes a small-number teaching exercise to illustrate the mathematical connection. It uses a fixed modulus (N=3233), factors (61) and (53), and a preselected period (r=260). The period and factor recovery are calculated with classical code. This provides a visible educational sequence, but it is intentionally much smaller and simpler than a cryptographic RSA key.

### 4.2 NIST post-quantum standards

NIST FIPS 203 standardizes ML-KEM, a key-encapsulation mechanism based on the Module Learning with Errors problem.[2] A KEM does not encrypt an arbitrarily large file directly. It allows parties to establish shared secret material, which can then be used with symmetric cryptography. VaultIQ follows this pattern by using ML-KEM-derived material to wrap a per-file AES key.

NIST FIPS 204 standardizes ML-DSA, a module-lattice-based digital-signature algorithm.[3] A digital signature allows a verifier to detect unauthorized changes to signed information and to check that it was produced using the corresponding signing key. VaultIQ signs canonical file metadata rather than using ML-DSA to encrypt file contents.

These standards establish algorithm specifications; they do not certify this application or its implementation. Using a standardized algorithm is one part of security engineering. Correct parameter handling, safe key storage, sound protocol design, implementation quality, testing, and deployment practices are also necessary.

### 4.3 Authenticated encryption with AES-GCM

NIST SP 800-38D specifies Galois/Counter Mode, an authenticated-encryption mode for block ciphers.[4] Authenticated encryption is useful for file protection because it provides confidentiality and detects certain modifications to ciphertext or associated data when correctly configured. VaultIQ uses AES-GCM for file bytes and checks its authentication tag during recovery.

The use of GCM requires careful nonce management: a nonce must not be reused with the same key. VaultIQ creates a fresh per-file AES key and a unique nonce for each encryption operation. The project’s documentation describes these as 256-bit AES keys and 96-bit nonces. An independent review would still be required to assess all implementation details, error paths, persistence behavior, and operational assumptions.

### 4.4 Hybrid or envelope encryption

Public-key operations are generally not used to encrypt large file contents directly. A common design is envelope encryption: a symmetric key protects the data, and a public-key mechanism or key-management service protects the symmetric key. This approach combines the speed of symmetric encryption with public-key key establishment or key wrapping.

VaultIQ applies this principle with AES-GCM for file bytes and ML-KEM-derived material for wrapping each file’s AES key. A separate ML-DSA signature protects canonical metadata. This separation makes the roles of encryption, key establishment, and signature verification easier to explain.

### 4.5 Research gap and project contribution

The referenced standards define individual cryptographic algorithms and modes. VaultIQ is an educational integration exercise: it brings file encryption, key encapsulation, metadata signing, verified recovery, event records, and key migration into a single demonstration. The contribution is not a new cryptographic algorithm. It is a prototype workflow designed to make the interaction between standardized primitives and file-vault operations visible to students.

The project’s evidence should be interpreted as a demonstration of its configured behavior. It is not a formal proof of security, a benchmark of commercial products, or an empirical evaluation of post-quantum strength.

## 5. Proposed system

### 5.1 Overview

The proposed VaultIQ system is a local application in which a browser communicates with a Java backend. The browser selects and uploads a file. Java independently processes the file bytes and stores a protected record. The record contains encrypted file bytes and the information required to recover and verify them, while plaintext file contents are not written as the stored vault record.

The backend holds the active PQC key material in an encrypted key bundle. Account and session controls protect access to vault operations. When a fixed controlled test is accepted, the backend advances the key version and migrates existing records to new protection. The user can inspect the resulting status and events through the dashboard, self-healing page, and audit trail.

### 5.2 File upload and protection sequence

1. The user selects a file in the browser.
2. The browser displays basic file details and calculates a SHA-256 digest for comparison.
3. The file bytes are sent to the Java backend.
4. Java independently calculates SHA-256 and generates a random AES-256 file key and 96-bit nonce.
5. AES-GCM encrypts the file bytes and produces an authentication tag.
6. The active ML-KEM-768 key encapsulates shared secret material.
7. HKDF-SHA-256 derives wrapping material from the KEM secret; AES-GCM wraps the file key.
8. The backend builds canonical, length-prefixed metadata and signs it with ML-DSA-65.
9. The backend stores ciphertext, nonce, encapsulation, wrapped file key, metadata, and signature.
10. The browser displays the upload result and whether its digest matches the digest calculated by Java.

### 5.3 Recovery sequence

1. The user requests a protected record.
2. Java loads the associated key version and signed metadata.
3. Java verifies the ML-DSA signature before trusting metadata.
4. Java decapsulates the KEM material and derives the wrapping key.
5. Java unwraps the file key and decrypts the ciphertext using AES-GCM.
6. GCM authentication, recovered file length, and SHA-256 are checked.
7. The backend returns the file only when the required checks succeed.

### 5.4 Self-healing and migration sequence

The term “self-healing” in VaultIQ describes a controlled lifecycle workflow rather than autonomous threat detection. A fixed test event is submitted to a project-owned endpoint. The backend validates that the evidence matches the configured toy target and accepted session. If validation succeeds, the backend creates a new ML-KEM/ML-DSA key version, processes existing files, verifies migrated records, updates active references, retires the prior PQC private-key version, and records the results.

If any migration verification fails, a safe production design should preserve enough old material and backups to recover rather than silently retire it. The prototype includes verified backups and reports status, but it is not an independently reviewed production key-migration system.

### 5.5 Remote lab sequence

Computer A runs the vault server on a private lab network. Computer B runs the authorized client. The connection uses HTTPS/TLS 1.3 and mutual TLS certificates. The server checks the client’s configured IP address and a bearer token. The client requests the project’s fixed challenge and submits only evidence for the fixed toy RSA target. A successful accepted event triggers the backend migration flow on Computer A.

This remote path is distinct from the local browser-based teaching workflow. It does not provide a general-purpose network scanning or arbitrary-target attack facility.

### 5.6 Main use cases

#### Use case A: Protect a file

**Actor:** signed-in vault user. **Precondition:** the server is running and the vault is unlocked. **Main flow:** the user selects a non-sensitive demonstration file; the browser calculates a digest and displays the file size; the backend receives the bytes and performs the protection steps; the backend stores the record; the browser displays the protection algorithm and digest comparison. **Postcondition:** the user can see a protected record, while its file payload is stored encrypted. If an operation fails, the interface reports the failure and does not represent an incomplete record as successfully protected.

#### Use case B: Inspect a protected record

**Actor:** signed-in vault user. The user opens the file view and selects a record. The application displays allowed metadata such as the protection algorithms, key version, status, and signature-verification result. Secret key bytes and the plaintext file key are not displayed. This use case supports explanation and troubleshooting without exposing cryptographic secrets through the normal inspection interface.

#### Use case C: Recover a file

**Actor:** signed-in vault user. The user requests recovery for a selected protected record. The backend validates the signed metadata, unwraps the data key, decrypts the payload, and checks the authentication tag, length, and digest. Only after those checks succeed does the backend send the file. If a check fails, recovery should stop and return an error instead of releasing unverified plaintext.

#### Use case D: Run the local controlled walkthrough

**Actor:** student or presenter. The user launches the local Attack Lab, enters a short text message for the RSA teaching view, and proceeds through the RSA and Shor pages. The pages demonstrate encryption arithmetic and a tiny fixed factorization example. For a vault-integrated local session, the backend issues a one-use session and later validates fixed test evidence. The demonstration explains which operations are calculations and which backend state transitions are real.

#### Use case E: Run the two-computer lab

**Actors:** Computer A operator and Computer B operator. Computer A starts the explicitly configured HTTPS server and keeps the private lab token and server material private. Computer B uses the client certificate, truststore, matching token, and target address. The server authenticates the TLS peer, checks the configured client address and token, and accepts only the fixed project evidence. The workflow is successful only if these checks pass and the backend reports an accepted event.

#### Use case F: Review self-healing evidence

**Actor:** signed-in user or project evaluator. The user opens the self-healing and audit views. The timeline derives its milestones from persisted backend events; the dashboard shows current key version and file count. The evaluator can compare what the interface reports with the client output and application audit records. A status label alone should not be treated as independent proof of security.

### 5.7 User roles and responsibilities

The prototype primarily supports a single local account. In a classroom demonstration, the **operator** configures and starts the server, protects a harmless sample file, and safeguards the temporary lab credentials. The **client operator** runs the fixed authorized client from Computer B. The **viewer/evaluator** observes the UI and examines recorded evidence. These are presentation roles rather than production-grade role-based access controls; the current account model is not a multi-tenant organization system.

## 6. System architecture

### 6.1 Logical components

| Component | Responsibility | Main input/output |
|---|---|---|
| Browser interface | File selection, status display, account entry, and educational views | User actions and JSON/API responses |
| Java HTTP server | Routes requests, applies session and remote-lab checks, returns responses | HTTP/HTTPS requests and responses |
| Vault service | Encrypts, signs, verifies, recovers, migrates, and records vault operations | File bytes, metadata, key state, and operation results |
| PQC key bundle | Holds active and versioned ML-KEM/ML-DSA key material encrypted at rest | Key generation, encapsulation, decapsulation, signing, verification |
| File-record storage | Stores protected file artifacts and migration backups | Ciphertext, nonce, wrapped key, encapsulation, metadata, signature |
| Audit storage | Persists event and operation metadata for review | Time, action, version, record, and result information |
| Remote lab client | Connects from Computer B and submits fixed authorized test evidence | TLS/mTLS connection and fixed challenge evidence |
| VaultAI | Answers project/security questions with sanitized context | User question, bounded chat history, and allowlisted status metadata |

### 6.2 Architecture flow

```text
                    ┌─────────────────────────────┐
                    │ Browser: VaultIQ interface  │
                    │ upload · status · recovery  │
                    └──────────────┬──────────────┘
                                   │ same-origin HTTP(S)
                                   ▼
                    ┌─────────────────────────────┐
                    │ Java HTTP server and API    │
                    │ sessions · validation · UI  │
                    └───────┬─────────────┬───────┘
                            │             │
               file/vault API             │ fixed lab API
                            │             │
                            ▼             ▼
              ┌────────────────────┐   ┌──────────────────────┐
              │ Vault service      │   │ Computer B lab client│
              │ AES-GCM · ML-KEM   │   │ TLS 1.3 · mTLS · token│
              │ ML-DSA · migration │   └──────────────────────┘
              └──────────┬─────────┘
                         │
             ┌───────────┴────────────┐
             ▼                        ▼
     ┌────────────────┐      ┌────────────────┐
     │ Protected file │      │ Encrypted keys │
     │ records/backups│      │ audit metadata │
     └────────────────┘      └────────────────┘
```

### 6.3 Deployment boundary

The project’s default launch mode is loopback-only. The two-computer mode is separately configured and gated. The remote mode should be used only on a private lab network with the generated short-lived certificates and a known client address. The project does not provide a production-grade certificate authority, enterprise network policy, or external audit infrastructure.

### 6.4 Data flow and trust boundaries

The browser is treated as an interface, not as the cryptographic authority. It can request operations and display results, but the Java backend independently calculates file hashes, performs cryptographic operations, validates fixed test evidence, and changes key state. This separation is important because client-side code can be inspected or modified by a user; critical validation therefore belongs on the server.

The principal trust boundaries are:

1. **Browser to local server:** requests are same-origin. Vault operations require the authenticated browser session.
2. **Computer B to Computer A:** remote requests require the explicitly enabled HTTPS lab, mutual TLS, an exact allowlisted source address, and a bearer token.
3. **Application to local storage:** the backend reads and writes encrypted records, backups, key bundle, and audit metadata. Filesystem permissions and host security remain important assumptions.
4. **Application to optional AI provider:** if provider-backed responses are enabled, the server sends the question, bounded conversation, and selected sanitized metadata. The provider does not receive file bytes, filenames, hashes, passwords, or private keys under the documented implementation.

The system does not protect against a fully compromised host operating system, malicious administrator, stolen account password, malicious Java runtime, storage-device failure, or all forms of side-channel attack. These boundaries should be included in a threat model rather than hidden by the use of strong algorithms.

## 7. Implementation details

### 7.1 Development environment

The maintained source is under `frontend/` and the Java backend source is under `backend/`. The project uses a full JDK version that provides ML-KEM and ML-DSA (the README specifies JDK 24 or later), Windows launch scripts, HTML, CSS, and JavaScript. No external Java cryptography package is required for the described JDK-provider operations.

### 7.2 Browser layer

The browser provides the message lab and VaultIQ pages for the dashboard, file records, upload, cryptographic process, PQC, monitoring, Attack Lab, remote demonstration, self-healing, recovery, audit, and VaultAI. Client-side code displays results and submits requests to the Java backend. File contents are processed by Java for the actual file-vault operation; the browser’s SHA-256 value is used for a comparison with the backend’s independent digest.

### 7.3 Backend API and service layer

The Java HTTP server routes requests for uploads, file records, recovery, status, keys, audit events, attack-session creation, fixed threat evidence, and the assistant. The vault service owns cryptographic and persistence operations. Validation occurs on the backend so that browser interface changes alone cannot produce accepted self-healing evidence.

The fixed remote lab endpoints are separate from the regular authenticated vault API. They require remote mode, TLS, a verified client certificate, the configured source address, and a valid bearer token. This reduces the remote demonstration’s scope to the configured lab client and fixed target.

### 7.4 File encryption and key wrapping

For each file, the backend generates a random 256-bit AES key and a 96-bit nonce. AES/GCM/NoPadding encrypts the file bytes. The resulting GCM authentication tag is kept with the ciphertext so altered ciphertext can be rejected during recovery.

The active ML-KEM-768 public key is used for encapsulation. The shared secret is passed through HKDF-SHA-256 to derive key-wrapping material. AES-GCM then wraps the file key. The KEM operation establishes key material; it does not directly encrypt the full file.

### 7.5 Metadata signatures

Metadata includes information needed to identify and verify the protected record, such as the file digest, version, original name and type, size, algorithm labels, and timestamp. The backend encodes canonical metadata in a length-prefixed format and signs it using ML-DSA-65. Canonicalization makes the bytes that are signed and later verified deterministic.

The signature supports integrity and authenticity checks for the metadata. It does not encrypt metadata and does not by itself protect file bytes; AES-GCM provides encryption and authentication for the encrypted file payload.

### 7.6 Account and key-bundle protection

The project uses a password verifier based on salted PBKDF2-HMAC-SHA-256. Its documentation describes 600,000 iterations and an AES-GCM encrypted key bundle. Web sessions use random HttpOnly, SameSite cookies with a one-hour lifetime and are revoked on logout, process restart, and validated self-healing events. These measures are part of the prototype design; they should not be treated as a substitute for a security review or hardware-backed key storage.

### 7.7 Controlled self-healing implementation

The backend accepts evidence only for the fixed project target. In the two-computer workflow, the client validates the challenge and sends evidence using the configured secure channel. In the local workflow, the browser uses one-use attack-session data and the Shor teaching page submits the fixed evidence to the backend.

On acceptance, the backend creates a fresh ML-KEM-768 and ML-DSA-65 version. It recovers old file content through verification, re-encrypts each file with a fresh AES key and the new KEM envelope, signs new canonical metadata, verifies the migrated record, switches the active file references, and retires the previous PQC key version. Event records describe important transitions.

### 7.8 Audit and monitoring

The audit view presents persisted application events and operation measurements. Events can describe upload, verification, recovery, test sessions, migration, and key lifecycle actions. The user interface is a view of backend records rather than an independent security sensor. The project documentation notes that its audit data is stored locally and is not cryptographically chained or remotely witnessed.

### 7.9 VaultAI assistant

VaultAI can answer using a deterministic local knowledge fallback. If configured with the server-side `OPENAI_API_KEY`, it can call the OpenAI Responses API and use an optional configured model. The backend sends sanitized security metadata and bounded recent conversation history. It does not send file contents, filenames, file hashes, passwords, or private keys. Provider failures return the local fallback. Assistant responses are advisory and cannot trigger recovery, key rotation, upload, or deletion.

### 7.10 Demonstration observations

In the recorded two-computer demonstration, the client established the configured HTTPS connection and submitted evidence for the fixed toy target. The server reported `PQC_ACTIVE`, advanced the active key version from v1 to v2, and migrated one protected file. The dashboard showed one protected file and one controlled test. These values describe that demonstration run only; they are not universal performance or security results.

### 7.11 Verification approach and test scenarios

Verification should cover both expected successful operations and rejection paths. The table distinguishes the evidence available from the demonstrated run from additional scenarios that should be run in a formal evaluation. “Recommended” does not mean the scenario has already been executed.

| Test ID | Scenario | Expected result | Evidence/status |
|---|---|---|---|
| VT-01 | Upload a harmless sample file | Backend stores a protected record and browser/backend SHA-256 values agree | Demonstrated in the provided UI screenshot |
| VT-02 | Connect from Computer B using configured TLS client credentials | HTTPS connection succeeds and the server returns the fixed project challenge | Demonstrated in the client output |
| VT-03 | Submit accepted fixed toy evidence | Server reports accepted lab event and initiates the configured migration | Demonstrated in the client output |
| VT-04 | Complete migration with one existing protected file | New version becomes active and migrated file is reported | Demonstrated: `PQC_ACTIVE`, v1 to v2, one migrated file |
| VT-05 | Review dashboard after migration | UI reports active key version and protected-file count consistent with backend | Demonstrated in the provided dashboard screenshot |
| VT-06 | Recover a migrated file and compare with original | Signature, GCM tag, length, and digest checks pass; content matches | Recommended additional recorded test |
| VT-07 | Modify ciphertext before recovery | GCM authentication fails and plaintext is not returned | Recommended controlled tamper test |
| VT-08 | Modify signed metadata | ML-DSA verification fails and the record is rejected | Recommended negative test |
| VT-09 | Connect without the correct client certificate, source IP, or token | Remote endpoint rejects the client | Recommended remote-lab negative tests |
| VT-10 | Interrupt migration during a file operation | System preserves recoverability and reports an incomplete migration safely | Recommended resilience/fault-injection test |
| VT-11 | Repeat the fixed test after old session/key retirement | Repeat path is logged and the retired test session is not accepted as a new initial event | Demonstrated in a later repeat run; review the matching audit records |

The evidence for VT-01 through VT-05 comes from the user-provided screenshots and terminal output in the lab demonstration. It is not a substitute for automated tests or independent validation. VT-06 through VT-10 are useful additions for a complete project evaluation. A report should attach sanitized screenshots or logs for each test actually run and clearly mark all remaining tests as pending.

### 7.12 Performance measurement methodology

The interface reports backend timings for operations such as SHA-256 hashing, AES-GCM encryption, ML-KEM key wrapping, ML-DSA signing, upload total, migration, and recovery. A performance result depends on the processor, JDK version, provider implementation, file size, storage speed, and background load. A single observed number should therefore be reported with its environment and should not be presented as a universal algorithm comparison.

A repeatable study could use at least three file-size groups (small text, medium document, and a larger file within the application’s upload limit), warm up the runtime before recording, repeat each operation several times, and report median and range. The study should separate file I/O from cryptographic operation time when possible. It should also report failed operations and not discard slow results without explanation. The project’s current timings are useful for illustrating what the application measures, but do not by themselves establish that one algorithm is faster or safer than another.

### 7.13 Demonstration procedure for evaluation

An evaluator can reproduce the visible workflow in the following order:

1. Start the Java server in its intended demonstration mode and open the printed URL.
2. Sign in to the local VaultIQ account and protect a harmless, non-sensitive sample file.
3. Show the upload response and compare the browser digest with the backend digest.
4. Open the dashboard and note the current vault status, key version, and protected-file count.
5. For the remote version, prepare the private lab credentials and start Computer A’s authorized server; Computer B then runs the fixed client once.
6. Show Computer B’s output indicating the controlled client request was accepted.
7. Return to Computer A, sign in again if sessions were revoked, and refresh the dashboard.
8. Open Self-Healing to show persisted migration milestones and Audit Trail to show associated records.
9. If approved for the demonstration, recover the migrated sample and verify its digest against the original.

The presenter should keep passwords, tokens, private keystores, and personal file contents off-screen. The explanation should describe the client operation as a fixed educational test and the key migration as the system behavior being demonstrated, not as proof of a real quantum attack.

## 8. Comparison with existing systems

The following comparison uses a simplified conventional file-encryption workflow as a baseline. Existing commercial and open-source products vary substantially; this table is not a measured product evaluation.

| Feature | Simplified conventional baseline | VaultIQ prototype |
|---|---|---|
| Bulk file encryption | Uses a symmetric cipher; implementation depends on the system | AES-256-GCM with per-file key and nonce |
| Public-key key establishment | May use classical RSA or elliptic-curve schemes | ML-KEM-768 is used to establish wrapping material |
| Metadata integrity | May use a hash or an application-specific signature | Canonical metadata is signed with ML-DSA-65 |
| Recovery checks | Vary by implementation | Signature, key unwrap, GCM authentication, length, and SHA-256 checks are included |
| Key replacement | Often configured separately from file migration | Demonstrates key-version change with record migration and verification |
| Event visibility | May rely on system logs or vendor UI | Provides project views over persisted local audit events |
| Remote lab | Not necessarily part of a file-encryption product | Includes a separately gated two-computer educational client |
| Quantum demonstration | Usually outside file-vault workflows | Includes a fixed classical toy RSA/Shor lesson, labeled as simulation |
| Security assurance | Depends on product evaluation and operational deployment | Educational prototype; no independent security review |

VaultIQ’s main distinction is that it combines several educational workflows in one project and shows the migration sequence. This does not mean it is more secure than existing products. Mature products may provide stronger auditing, identity integration, key custody, availability, and independent evaluation.

## 9. Advantages of the proposed system

### 9.1 Clear separation of cryptographic roles

The design uses AES-GCM for bulk file encryption, ML-KEM for key establishment and wrapping, and ML-DSA for metadata signatures. This division helps explain why a KEM is not a bulk file cipher and why a signature is not an encryption mechanism.

### 9.2 Authenticated file protection

AES-GCM provides a confidentiality and ciphertext-integrity check when used with appropriate key and nonce handling. The backend checks the authentication tag before it returns a recovered file.

### 9.3 Signed metadata

Signing canonical metadata gives the application a check for unauthorized changes to record information. This complements payload encryption and authentication.

### 9.4 Verified migration sequence

The controlled lifecycle demonstrates that key rotation involves more than generating a new key. Stored records must be recovered, checked, transformed, re-signed, verified, and only then moved to the new active version.

### 9.5 Educational visibility

The interface shows cryptographic stages, recorded events, active key version, migration status, and verification results. This makes the prototype suitable for classroom explanation and project demonstrations.

### 9.6 Restricted remote demonstration

Mutual TLS, an IP allowlist, a token, and fixed-target validation constrain the two-computer demonstration. This is a more controlled setup than exposing a generic unauthenticated endpoint to the network.

### 9.7 Explicit limits

The project labels the Shor path as classical and toy-sized and documents that it is not production software. Accurate limitations reduce the risk of overstating what the demonstration proves.

## 10. Future scope

1. **Independent security assessment:** Review the threat model, Java cryptographic calls, session handling, file storage, migration recovery, remote endpoints, and error handling.
2. **Automated verification:** Add repeatable tests for malformed records, tampered ciphertext, invalid signatures, wrong key versions, interrupted migration, and recovery failures.
3. **Crash-safe migration:** Formalize transactional migration and rollback so every possible interruption leaves a recoverable state. Validate this through fault-injection testing.
4. **Hardened key custody:** Evaluate an HSM, OS-backed keystore, or managed key service instead of relying only on a locally encrypted key bundle.
5. **Audit protection:** Add integrity chaining, remote log forwarding, or append-only external storage. The current local event log is not independently anchored.
6. **Account recovery and administration:** Add carefully designed recovery options, multiple users, role-based access, account lockout controls, and administrative audit trails.
7. **Operational resilience:** Add backup policies, retention, restore drills, disk-full behavior, and monitoring for service failures.
8. **Interoperability:** Evaluate hybrid classical and post-quantum key establishment, certificate lifecycle, and compatibility with other runtimes and clients.
9. **Broader file handling:** Evaluate large files, streaming encryption, concurrent uploads, cancellation, and safe handling of unusual MIME types and filenames.
10. **Performance study:** Measure upload, encapsulation, encryption, signature, migration, and recovery over multiple machines, file sizes, and repeated runs. Report distributions and environment details.
11. **AI assistant improvements:** Add provider configuration guidance and clearer local-versus-provider status while keeping secrets server-side and minimizing transmitted context.
12. **Accessibility and usability:** Conduct keyboard, screen-reader, contrast, mobile-layout, and user-comprehension reviews.
13. **Formal production plan:** Define compliance requirements, secure development practices, incident response, vulnerability handling, and deployment controls before any production use.

## 11. Results and discussion

### 11.1 Demonstration results

The successful remote demonstration provides a concrete end-to-end result for the configured lab. Computer B connected to Computer A over HTTPS using the configured client certificate and truststore. The client received the project-owned challenge, processed the fixed toy RSA values, checked the recovered challenge hash, and submitted the evidence to the fixed backend endpoint. The server accepted the event and reported the completed migration state.

The reported state included `PQC_ACTIVE`, `oldVersion` 1, `keyVersion` 2, and `migratedFiles` 1. The dashboard later showed the new active key version and one protected file. These observations confirm that the particular demonstration completed as configured. They do not establish that every failure case is safe, that the algorithm implementation is certified, or that a real quantum computation took place.

### 11.2 Interpretation of the hybrid design

The project uses multiple algorithms because the file-vault tasks differ. AES-GCM handles the bulk data. ML-KEM establishes secret material for key wrapping. ML-DSA authenticates metadata. SHA-256 supplies a digest for comparison and file-integrity evidence. Combining them in this way is a design pattern, not a claim that simply selecting standardized algorithms guarantees application security.

The key migration path is valuable for teaching because it connects key replacement to stored data. A new key cannot protect old records until those records have been migrated, and an old key should not be retired before the new records have been verified. This sequence creates operational concerns such as failure recovery, transaction boundaries, disk capacity, backups, and consistency between active pointers and record versions. Those concerns need further testing in a production system.

### 11.3 Threat model and protected assets

The primary assets are file confidentiality, file integrity, authenticity of metadata, private PQC key material, account credentials, lab tokens, and correctness of key-version state. The project includes controls intended to reduce selected risks, but does not attempt to address every threat.

| Threat or failure | Prototype control or boundary | Remaining concern |
|---|---|---|
| Unauthorized reading of stored file bytes | AES-GCM encrypts file content before record storage | Host compromise, plaintext while processing, and storage permissions remain relevant |
| Ciphertext modification | GCM authentication is checked during recovery | Negative testing and independent implementation review are still needed |
| Metadata modification | Canonical metadata is signed with ML-DSA-65 | Signature key custody and canonicalization must be reviewed |
| Wrong or obsolete key version | Records include version information; migration updates the active version | Interrupted updates and rollback behavior require additional testing |
| Unauthorized web access | Authenticated browser session protects vault API routes | Single-user account model and local host security are limitations |
| Unauthorized remote client | TLS client certificate, source IP, bearer token, fixed endpoint | Private network configuration and credential handling remain operator responsibilities |
| Reuse of old test evidence | One-use session and repeat-event logic | Must be tested against malformed, expired, and replayed requests |
| Loss of local disk or vault bundle | Local backups are part of the prototype design | Off-host disaster recovery and restore procedures are not established |
| False interpretation of the Shor lesson | UI and documentation label it a classical toy simulation | Presenter must maintain this distinction in reports and demos |

The design does not claim to protect against a compromised host, malicious administrator, malware with access to an unlocked account, insecure backups, physical theft of an unlocked computer, denial of service, or all side-channel attacks. The remote lab’s certificates and token are temporary demo credentials and should be protected as secrets.

### 11.4 Failure handling and recovery considerations

Cryptographic applications must define what happens when a check fails. A signature failure means metadata should not be trusted. A GCM tag failure means the ciphertext must not be returned as valid plaintext. A digest mismatch means the recovered file does not match the expected content. An unavailable key means recovery cannot continue. A failure during migration must not silently mark the old key as retired while some files still depend on it.

For a production-ready design, migration should use an explicit state machine and transactional persistence. It should record which records have been verified, which have been transformed, whether the active key pointer has changed, and whether retirement is safe. It should define restart behavior for every stage. The prototype displays migration events and uses backups, but these mechanisms need exhaustive interruption and restoration tests before they could support a real operational guarantee.

### 11.5 Privacy and AI-provider boundary

VaultAI is an optional educational assistant, not part of the file encryption or recovery trust path. The deterministic local fallback can answer a limited set of project and security questions. If provider-backed generation is enabled, the backend sends the question, a bounded recent conversation, and allowlisted security metadata to the configured provider. The project documentation says file contents, filenames, hashes, passwords, and private keys are excluded from that context.

Users should understand whether a response came from the local fallback or the configured AI provider. The assistant is advisory and cannot perform vault operations. It should not be relied upon as a cryptographic verifier, incident detector, or authoritative source for whether a file is safe. Security decisions remain with backend checks and human review.

### 11.6 Usability and educational value

The application separates upload, recovery, PQC operations, attack demonstration, self-healing, and audit views so an evaluator can follow each stage. The updated interface also provides direct access to VaultAI from the main page. Visual clarity can support learning, but interface labels must remain precise: “controlled test” and “classical simulation” are more accurate than implying that the application detected an actual quantum attacker.

The most effective presentation follows the sequence of input, protection, test evidence, migration, verification, and audit review. Each displayed status should be connected to a backend event or explicit API response. A screenshot is useful as presentation evidence, while terminal output and a repeatable procedure provide additional context.

### 11.7 Overall assessment

VaultIQ demonstrates a useful integration path for learning about post-quantum file protection and key lifecycle changes. Its strongest educational value is the visible relationship between data encryption, key wrapping, metadata signatures, recovery verification, and migration. Its most important limitation is that it remains a local prototype with limited account management, local audit storage, demo-specific remote credentials, and no independent security review. Its outputs should be presented as evidence of a controlled prototype run, not as generalized security certification.

## 12. Conclusion

VaultIQ is an educational prototype for understanding how post-quantum primitives can participate in a file-protection and key-lifecycle workflow. AES-256-GCM protects file bytes, ML-KEM-768 provides key-establishment material for wrapping per-file keys, and ML-DSA-65 signs canonical metadata. Recovery is conditioned on signature, authentication-tag, length, and digest checks.

The project’s controlled self-healing demonstration adds a migration sequence: validate fixed test evidence, create a new key version, migrate and verify stored records, update active references, and retire old PQC key material. Its two-computer lab demonstrates a restricted HTTPS mutual-TLS client connection. The observed test run advanced to PQC_ACTIVE and migrated one protected file.

These results show the prototype’s demonstration behavior, not its readiness for production. Its RSA/Shor exercise uses a fixed small number and classical calculations, and the project is not a quantum attack detector. Future work should prioritize independent review, crash-safe migration, stronger audit protection, operational testing, and an explicit path toward hardened key management.

## References

1. P. W. Shor, “Algorithms for Quantum Computation: Discrete Logarithms and Factoring,” *Proceedings of the 35th Annual Symposium on Foundations of Computer Science*, 1994, pp. 124–134. [https://doi.org/10.1109/SFCS.1994.365700](https://doi.org/10.1109/SFCS.1994.365700).
2. National Institute of Standards and Technology, *FIPS 203: Module-Lattice-Based Key-Encapsulation Mechanism Standard*, August 2024. [NIST CSRC publication page](https://csrc.nist.gov/pubs/fips/203/final).
3. National Institute of Standards and Technology, *FIPS 204: Module-Lattice-Based Digital Signature Standard*, August 2024. [NIST CSRC publication page](https://csrc.nist.gov/pubs/fips/204/final).
4. M. Dworkin, *NIST Special Publication 800-38D: Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM) and GMAC*, November 2007. [NIST CSRC publication page](https://csrc.nist.gov/pubs/sp/800/38/d/final).
5. National Institute of Standards and Technology, “Announcing Approval of Three Federal Information Processing Standards (FIPS) for Post-Quantum Cryptography,” August 13, 2024. [NIST CSRC announcement](https://csrc.nist.gov/News/2024/postquantum-cryptography-fips-approved).
6. VaultIQ project source and implementation notes, [`README.md`](README.md), accessed October 8, 2026.

---

**Report note:** This report describes an educational prototype. Update the institution, author, guide, implementation environment, test evidence, and formatting to match your submission requirements. Do not describe the toy RSA/Shor simulation as a real quantum attack or the prototype as independently certified or production-ready.
