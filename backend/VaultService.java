import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.NamedParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.math.BigInteger;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.TreeMap;
import java.util.UUID;
import javax.crypto.Cipher;
import javax.crypto.KEM;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.AEADBadTagException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

final class VaultService {
    static final int MAX_FILE_BYTES = 16 * 1024 * 1024;
    static final String NETWORK_TEST_MESSAGE = "AUTHORIZED PQC VAULT RSA LAB 3233";
    private static final int KEY_BUNDLE_ITERATIONS = 600_000;
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final String[] PACKAGE_FILES = {
            "ciphertext.bin", "nonce.bin", "file-key-wrap.bin", "wrap-nonce.bin",
            "wrap-salt.bin", "encapsulation.bin", "metadata.properties", "signature.bin"
    };

    private final Path root;
    private final Path recordsRoot;
    private final Path backupRoot;
    private final Path bundleFile;
    private final Path vaultPropertiesFile;
    private final Path auditFile;
    private final Path accountFile;
    private final TreeMap<Integer, KeyPair> kemKeys = new TreeMap<>();
    private final TreeMap<Integer, KeyPair> signingKeys = new TreeMap<>();
    private final Map<String, String> attackSessions = new LinkedHashMap<>();
    private final List<Map<String, Object>> events = new ArrayList<>();
    private SecretKey bundleWrappingKey;
    private byte[] bundleSalt;
    private int keyVersion;
    private String state = "LOCKED";
    private boolean unlocked;

    VaultService(Path root) throws IOException {
        this.root = root.toAbsolutePath().normalize();
        recordsRoot = this.root.resolve("records");
        backupRoot = this.root.resolve("backups");
        bundleFile = this.root.resolve("keys.bundle");
        vaultPropertiesFile = this.root.resolve("vault.properties");
        auditFile = this.root.resolve("audit.log");
        accountFile = this.root.resolve("account.properties");
        Files.createDirectories(recordsRoot);
        Files.createDirectories(backupRoot);
        loadVaultState();
        loadEvents();
    }

    synchronized Map<String, Object> status() {
        Map<String, Object> result = map(
                "unlocked", unlocked,
                "state", unlocked ? state : "LOCKED",
                "keyVersion", keyVersion,
                "fileCount", unlocked ? currentRecordIds().size() : 0,
                "javaVersion", Runtime.version().feature(),
                "kem", "ML-KEM-768",
                "signature", "ML-DSA-65");
        result.put("accountConfigured", Files.exists(accountFile));
        result.put("keyBundleConfigured", Files.exists(bundleFile));
        return result;
    }

    synchronized Map<String, Object> register(String username, char[] password) throws Exception {
        String normalized = validateUsername(username);
        if (unlocked) {
            Arrays.fill(password, '\0');
            throw new IllegalStateException("Sign out and restart the server before registering an account for an existing unlocked vault.");
        }
        if (Files.exists(accountFile)) {
            Arrays.fill(password, '\0');
            throw new IllegalStateException("An account already exists. Sign in with its credentials.");
        }
        if (password.length < 12) {
            Arrays.fill(password, '\0');
            throw new IllegalArgumentException("Use an account password with at least 12 characters.");
        }
        unlock(password.clone());
        saveAccount(normalized, password);
        Arrays.fill(password, '\0');
        recordEvent("ACCOUNT_REGISTERED", "", keyVersion, "USERNAME=" + normalized);
        Map<String, Object> result = status();
        result.put("username", normalized);
        result.put("registered", true);
        return result;
    }

    synchronized Map<String, Object> login(String username, char[] password) throws Exception {
        String normalized = validateUsername(username);
        Properties account = loadProperties(accountFile);
        byte[] salt;
        byte[] expected;
        try {
            if (!normalized.equals(account.getProperty("username"))) throw new GeneralSecurityException();
            salt = Base64.getDecoder().decode(account.getProperty("salt", ""));
            expected = Base64.getDecoder().decode(account.getProperty("verifier", ""));
            if (salt.length != 16 || expected.length != 32) throw new GeneralSecurityException();
            byte[] actual = passwordVerifier(password, salt);
            if (!MessageDigest.isEqual(expected, actual)) throw new GeneralSecurityException();
            Arrays.fill(actual, (byte) 0);
        } catch (Exception exception) {
            Arrays.fill(password, '\0');
            throw new IllegalArgumentException("Username or password is incorrect.");
        }
        unlock(password);
        recordEvent("ACCOUNT_LOGIN", "", keyVersion, "USERNAME=" + normalized);
        Map<String, Object> result = status();
        result.put("username", normalized);
        result.put("loggedIn", true);
        return result;
    }

    private String validateUsername(String username) {
        String normalized = username == null ? "" : username.strip();
        if (!normalized.matches("[A-Za-z0-9][A-Za-z0-9._-]{2,39}")) {
            throw new IllegalArgumentException("Username must be 3 to 40 letters, numbers, dots, underscores, or hyphens.");
        }
        return normalized;
    }

    private void saveAccount(String username, char[] password) throws Exception {
        byte[] salt = randomBytes(16);
        byte[] verifier = passwordVerifier(password, salt);
        Properties account = new Properties();
        account.setProperty("username", username);
        account.setProperty("salt", Base64.getEncoder().encodeToString(salt));
        account.setProperty("verifier", Base64.getEncoder().encodeToString(verifier));
        account.setProperty("iterations", Integer.toString(KEY_BUNDLE_ITERATIONS));
        storeProperties(accountFile, account);
        Arrays.fill(verifier, (byte) 0);
    }

    private byte[] passwordVerifier(char[] password, byte[] salt) throws Exception {
        PBEKeySpec spec = new PBEKeySpec(password, salt, KEY_BUNDLE_ITERATIONS, 256);
        try { return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded(); }
        finally { spec.clearPassword(); }
    }

    synchronized Map<String, Object> keyStatus() throws Exception {
        requireUnlocked();
        KeyPair kemPair = kemKeys.get(keyVersion);
        KeyPair signaturePair = signingKeys.get(keyVersion);
        if (kemPair == null || signaturePair == null) throw new GeneralSecurityException("Active key version is unavailable.");
        return map("state", state, "keyVersion", keyVersion,
                "kem", "ML-KEM-768", "kemProvider", KeyPairGenerator.getInstance("ML-KEM").getProvider().getName(),
                "kemPublicKeyFormat", kemPair.getPublic().getFormat(),
                "kemPublicKeyBytes", kemPair.getPublic().getEncoded().length,
                "kemPublicKey", encode(kemPair.getPublic().getEncoded()),
                "signature", "ML-DSA-65", "signatureProvider", Signature.getInstance("ML-DSA").getProvider().getName(),
                "signaturePublicKeyFormat", signaturePair.getPublic().getFormat(),
                "signaturePublicKeyBytes", signaturePair.getPublic().getEncoded().length,
                "signaturePublicKey", encode(signaturePair.getPublic().getEncoded()),
                "privateKeysExported", false,
                "bundleEncryption", "PBKDF2-HMAC-SHA-256 + AES-256-GCM");
    }

    synchronized Map<String, Object> pqcSelfTest() throws Exception {
        requireUnlocked();
        KeyPair kemPair = kemKeys.get(keyVersion);
        KeyPair signingPair = signingKeys.get(keyVersion);
        if (kemPair == null || signingPair == null) throw new GeneralSecurityException("Active PQC key version is unavailable.");
        KEM.Encapsulated encapsulated = KEM.getInstance("ML-KEM")
                .newEncapsulator(kemPair.getPublic(), RANDOM).encapsulate();
        byte[] encapsulatedSecret = encapsulated.key().getEncoded();
        byte[] decapsulatedSecret = KEM.getInstance("ML-KEM")
                .newDecapsulator(kemPair.getPrivate()).decapsulate(encapsulated.encapsulation()).getEncoded();
        boolean sharedSecretMatches = MessageDigest.isEqual(encapsulatedSecret, decapsulatedSecret);
        String sharedSecretFingerprint = sha256Hex(encapsulatedSecret);
        Arrays.fill(encapsulatedSecret, (byte) 0);
        Arrays.fill(decapsulatedSecret, (byte) 0);
        byte[] signedMetadata = ("VAULTIQ-PQC-SELF-TEST\nkeyVersion=" + keyVersion
                + "\ncreatedAt=" + Instant.now()).getBytes(StandardCharsets.UTF_8);
        Signature signer = Signature.getInstance("ML-DSA");
        signer.initSign(signingPair.getPrivate(), RANDOM);
        signer.update(signedMetadata);
        byte[] signatureBytes = signer.sign();
        Signature verifier = Signature.getInstance("ML-DSA");
        verifier.initVerify(signingPair.getPublic());
        verifier.update(signedMetadata);
        boolean signatureValid = verifier.verify(signatureBytes);
        if (!sharedSecretMatches || !signatureValid) {
            recordEvent("PQC_SELF_TEST_FAILED", "", keyVersion,
                    "KEM_MATCH=" + sharedSecretMatches + " SIGNATURE_VALID=" + signatureValid);
            throw new GeneralSecurityException("The JDK PQC self-test verification failed.");
        }
        String metadataDigest = sha256Hex(signedMetadata);
        recordEvent("PQC_SELF_TEST_COMPLETED", "", keyVersion,
                "ML_KEM_ENCAPSULATION_DECAPSULATION_AND_ML_DSA_SIGNATURE_VERIFIED");
        return map("keyVersion", keyVersion,
                "kem", "ML-KEM-768", "kemProvider", KeyPairGenerator.getInstance("ML-KEM").getProvider().getName(),
                "kemPublicKeyFingerprint", sha256Hex(kemPair.getPublic().getEncoded()),
                "encapsulation", encode(encapsulated.encapsulation()),
                "encapsulationBytes", encapsulated.encapsulation().length,
                "sharedSecretFingerprint", sharedSecretFingerprint,
                "decapsulationMatches", sharedSecretMatches,
                "signatureAlgorithm", "ML-DSA-65",
                "signatureProvider", Signature.getInstance("ML-DSA").getProvider().getName(),
                "signingPublicKeyFingerprint", sha256Hex(signingPair.getPublic().getEncoded()),
                "metadataDigest", metadataDigest,
                "signature", encode(signatureBytes),
                "signatureBytes", signatureBytes.length,
                "signatureValid", signatureValid);
    }

    synchronized Map<String, Object> changePassphrase(char[] passphrase) throws Exception {
        requireUnlocked();
        if (passphrase.length < 12) {
            Arrays.fill(passphrase, '\0');
            throw new IllegalArgumentException("Use a new account password with at least 12 characters.");
        }
        char[] bundlePassphrase = passphrase.clone();
        try {
            persistKeyBundle(bundlePassphrase);
            Properties account = loadProperties(accountFile);
            if (account.getProperty("username") != null) saveAccount(account.getProperty("username"), passphrase);
            recordEvent("VAULT_PASSPHRASE_CHANGED", "", keyVersion, "KEY_BUNDLE_REWRAPPED");
            return map("updated", true, "message", "Encrypted PQC key bundle rewrapped with the new passphrase.");
        } finally {
            Arrays.fill(passphrase, '\0');
            Arrays.fill(bundlePassphrase, '\0');
        }
    }

    synchronized Map<String, Object> unlock(char[] passphrase) throws Exception {
        if (unlocked) {
            Arrays.fill(passphrase, '\0');
            return status();
        }
        if (passphrase.length < 10) {
            Arrays.fill(passphrase, '\0');
            throw new IllegalArgumentException("Use a vault passphrase with at least 10 characters.");
        }
        if (Files.exists(bundleFile)) {
            loadKeyBundle(passphrase);
        } else {
            if (keyVersion > 0 || !currentRecordIds().isEmpty()) {
                Arrays.fill(passphrase, '\0');
                throw new IOException("The encrypted vault key bundle is missing. Initialization was refused to protect existing files.");
            }
            keyVersion = 1;
            kemKeys.put(keyVersion, generateKeyPair("ML-KEM", "ML-KEM-768"));
            signingKeys.put(keyVersion, generateKeyPair("ML-DSA", "ML-DSA-65"));
            state = "PQC_BASELINE";
            persistKeyBundle(passphrase);
            persistVaultState();
            recordEvent("VAULT_INITIALIZED", "", keyVersion, "PQC_KEYS_CREATED");
        }
        unlocked = true;
        if (!"PQC_ACTIVE".equals(state) && !"HEALING_FAILED".equals(state)) {
            state = "PQC_BASELINE";
        }
        recordEvent("VAULT_UNLOCKED", "", keyVersion, "SUCCESS");
        return status();
    }

    synchronized Map<String, Object> upload(String filename, String contentType, byte[] bytes)
            throws Exception {
        requireUnlocked();
        if (!"PQC_BASELINE".equals(state) && !"PQC_ACTIVE".equals(state)) {
            throw new IllegalStateException("File protection is paused while the vault state is " + state + ".");
        }
        long uploadStarted = System.nanoTime();
        if (bytes.length == 0) throw new IllegalArgumentException("The selected file is empty.");
        if (bytes.length > MAX_FILE_BYTES) throw new IllegalArgumentException("Maximum upload size is 16 MiB.");
        String safeName = Path.of(filename.replace('\\', '/')).getFileName().toString();
        if (safeName.isBlank() || safeName.equals(".") || safeName.equals("..")) {
            throw new IllegalArgumentException("The uploaded filename is invalid.");
        }
        if (safeName.length() > 255) throw new IllegalArgumentException("Filename must be 255 characters or fewer.");
        String normalizedType = contentType == null || contentType.isBlank()
                ? "application/octet-stream" : contentType.substring(0, Math.min(contentType.length(), 160));
        String id = UUID.randomUUID().toString();
        int uploadVersion = keyVersion;
        long hashStarted = System.nanoTime();
        String hash = sha256Hex(bytes);
        double hashMillis = elapsedMillis(hashStarted);
        Path recordDir = recordDirectory(id);
        Files.createDirectories(recordDir);
        recordEvent("FILE_UPLOADED", id, keyVersion, "SIZE_" + bytes.length);
        recordEvent("HASH_GENERATED", id, keyVersion, "SHA256=" + hash);
        recordEvent("PERFORMANCE_SHA256", id, keyVersion, "ELAPSED_MS=" + hashMillis);
        Map<String, Object> details = protectVersion(id, uploadVersion, safeName, normalizedType, bytes, hash);
        @SuppressWarnings("unchecked")
        Map<String, Object> performance = (Map<String, Object>) details.get("performanceMs");
        performance.put("sha256", hashMillis);
        writeRecordPointer(id, uploadVersion, "ACTIVE");
        createBackup(id, uploadVersion);
        recordEvent("FILE_ENCRYPTED", id, uploadVersion, "AES_256_GCM");
        recordEvent("PERFORMANCE_AES_256_GCM", id, uploadVersion,
                "ELAPSED_MS=" + performance.get("aes256GcmEncryption"));
        recordEvent("PQC_PROTECTION_CREATED", id, uploadVersion, "ML_KEM_768_WRAPPED_AES_FILE_KEY");
        recordEvent("PERFORMANCE_ML_KEM_768", id, uploadVersion,
                "ELAPSED_MS=" + performance.get("kemAndKeyWrap"));
        recordEvent("FILE_SIGNED", id, uploadVersion, "ML_DSA_65");
        recordEvent("SIGNATURE_CREATED", id, uploadVersion, "ML_DSA_65_METADATA_SIGNATURE");
        recordEvent("PERFORMANCE_ML_DSA_65", id, uploadVersion,
                "ELAPSED_MS=" + performance.get("mldsa65Signing"));
        performance.put("uploadTotal", elapsedMillis(uploadStarted));
        recordEvent("PERFORMANCE_UPLOAD", id, uploadVersion, "ELAPSED_MS=" + performance.get("uploadTotal"));
        return details;
    }

    synchronized List<Map<String, Object>> listFiles() throws Exception {
        requireUnlocked();
        List<Map<String, Object>> result = new ArrayList<>();
        for (String id : currentRecordIds()) result.add(readDetails(id));
        result.sort(Comparator.<Map<String, Object>, String>comparing(
            item -> item.get("createdAt").toString()).reversed());
        return result;
    }

    synchronized Map<String, Object> fileDetails(String id) throws Exception {
        requireUnlocked();
        return readDetails(validateId(id));
    }

    synchronized Map<String, Object> deleteFile(String id) throws Exception {
        requireUnlocked();
        id = validateId(id);
        Path record = recordDirectory(id);
        if (!Files.isDirectory(record)) throw new IllegalArgumentException("File record was not found.");
        int version = currentVersion(id);
        deleteTree(record);
        deleteTree(backupRoot.resolve(id));
        recordEvent("FILE_DELETED", id, version, "ENCRYPTED_RECORD_AND_BACKUP_REMOVED");
        return map("id", id, "deleted", true);
    }

    synchronized void recordWebSessionsRevoked() throws IOException {
        recordEvent("WEB_SESSIONS_REVOKED", "", keyVersion, "PRIOR_BROWSER_SESSIONS_INVALIDATED_AFTER_THREAT");
    }

    synchronized DownloadResult recover(String id) throws Exception {
        requireUnlocked();
        id = validateId(id);
        long recoveryStarted = System.nanoTime();
        int version = currentVersion(id);
        Map<String, String> metadata = readMetadata(packageDirectory(id, version));
        byte[] plaintext = decryptAndVerify(id, version, metadata);
        recordEvent("FILE_RECOVERED", id, version, "SIGNATURE_AND_HASH_VALID");
        recordEvent("PERFORMANCE_RECOVERY", id, version, "ELAPSED_MS=" + elapsedMillis(recoveryStarted));
        recordEvent("RECOVERY_COMPLETED", id, version, "SIGNATURE_GCM_TAG_LENGTH_AND_SHA256_VALID");
        recordEvent("INTEGRITY_VERIFIED", id, version, "SHA256_MATCH");
        return new DownloadResult(metadata.get("filename"), metadata.get("contentType"), plaintext, metadata);
    }

    synchronized Map<String, Object> tamperAndRestore(String id) throws Exception {
        requireUnlocked();
        id = validateId(id);
        int version = currentVersion(id);
        Path packageDir = packageDirectory(id, version);
        Path ciphertext = packageDir.resolve("ciphertext.bin");
        byte[] protectedBytes = Files.readAllBytes(ciphertext);
        if (protectedBytes.length == 0) throw new IOException("Protected file is empty on disk.");
        protectedBytes[protectedBytes.length / 2] ^= 1;
        Files.write(ciphertext, protectedBytes);
        recordEvent("CONTROLLED_TAMPER", id, version, "ONE_CIPHERTEXT_BIT_CHANGED");
        boolean detected = false;
        try {
            decryptAndVerify(id, version, readMetadata(packageDir));
        } catch (AEADBadTagException | SecurityException exception) {
            detected = true;
        }
        if (!detected) {
            throw new GeneralSecurityException("Tampered ciphertext was not detected; backup was not used.");
        }
        recordEvent("TAMPERING_DETECTED", id, version, "AES_GCM_TAG_INVALID");
        restoreBackup(id, version);
        Map<String, String> metadata = readMetadata(packageDir);
        byte[] restored = decryptAndVerify(id, version, metadata);
        recordEvent("BACKUP_RESTORED", id, version, "SIGNATURE_AND_HASH_VALID");
        recordEvent("INTEGRITY_VERIFIED", id, version, "RESTORED_SHA256_MATCH");
        return map("id", id, "version", version, "tamperingDetected", true,
                "recoveredBytes", restored.length, "sha256", metadata.get("sha256"),
                "status", "BACKUP_RESTORED_AND_VERIFIED");
    }

    synchronized Map<String, Object> issueAttackSession(String purpose) throws IOException {
        requireUnlocked();
        if (!purpose.equals("initial") && !purpose.equals("repeat")) {
            throw new IllegalArgumentException("Attack session purpose is invalid.");
        }
        if (purpose.equals("initial") && !"PQC_BASELINE".equals(state)) {
            throw new IllegalStateException("The initial RSA test session is no longer active.");
        }
        if (purpose.equals("repeat") && !"PQC_ACTIVE".equals(state)) {
            throw new IllegalStateException("Complete self-healing before issuing a repeat-attack session.");
        }
        if (attackSessions.size() >= 16) attackSessions.clear();
        String token = UUID.randomUUID().toString();
        attackSessions.put(token, purpose);
        recordEvent("CONTROLLED_ATTACK_SESSION_ISSUED", "", keyVersion, purpose.toUpperCase(java.util.Locale.ROOT));
        return map("sessionId", token, "purpose", purpose, "expires", "ONCE_OR_SERVER_RESTART");
    }

    synchronized Map<String, Object> issueNetworkAttackSession(String purpose, String source,
                                                                String destination, String ciphertext)
            throws Exception {
        Map<String, Object> session = issueAttackSession(purpose);
        recordEvent("NETWORK_CONNECTION", "", keyVersion, "SOURCE=" + safeAuditValue(source)
                + " DESTINATION=" + safeAuditValue(destination)
                + " TARGET=PROJECT_RSA_3233 ENDPOINT=/api/lab/challenge");
        recordEvent("ATTACK_CHALLENGE_ISSUED", "", keyVersion,
                "SOURCE=" + safeAuditValue(source) + " DESTINATION=" + safeAuditValue(destination)
                        + " TARGET=PROJECT_RSA_3233 ENDPOINT=/api/lab/challenge PURPOSE="
                        + purpose.toUpperCase(java.util.Locale.ROOT));
        return map("sessionId", session.get("sessionId"), "purpose", purpose,
                "targetId", "PROJECT_RSA_3233", "modulus", 3233, "publicExponent", 17,
                "ciphertextNumbers", ciphertext,
                "recoveredSha256", sha256Hex(NETWORK_TEST_MESSAGE.getBytes(StandardCharsets.UTF_8)),
                "periodFinding", "Classical educational simulation only");
    }

    synchronized Map<String, Object> submitNetworkAttack(String purpose, String sessionId,
                                                         int modulus, int factor1, int factor2,
                                                         int period, String recoveredSha256,
                                                         String source, String destination) throws Exception {
        String expectedHash = sha256Hex(NETWORK_TEST_MESSAGE.getBytes(StandardCharsets.UTF_8));
        if (!MessageDigest.isEqual(expectedHash.getBytes(StandardCharsets.US_ASCII),
                recoveredSha256.toLowerCase(java.util.Locale.ROOT).getBytes(StandardCharsets.US_ASCII))) {
            consumeAttackSession(sessionId, purpose);
            recordEvent("NETWORK_ATTACK_REJECTED", "", keyVersion,
                    "SOURCE=" + safeAuditValue(source) + " DESTINATION=" + safeAuditValue(destination)
                            + " TARGET=PROJECT_RSA_3233 ENDPOINT=/api/lab/submit/" + purpose
                            + " TEST_PLAINTEXT_HASH_MISMATCH");
            throw new IllegalArgumentException("Recovered test-message hash did not match the server challenge.");
        }
        recordEvent(purpose.equals("repeat") ? "SECOND_ATTACK_DETECTED" : "NETWORK_ATTACK_DETECTED", "", keyVersion,
                "SOURCE=" + safeAuditValue(source) + " DESTINATION=" + safeAuditValue(destination)
                        + " TARGET=PROJECT_RSA_3233 ENDPOINT=/api/lab/submit/"
                        + purpose + " PERIOD=" + period);
        recordEvent("ATTACK_DETECTED", "", keyVersion,
                "SOURCE=" + safeAuditValue(source) + " DESTINATION=" + safeAuditValue(destination)
                        + " TARGET=PROJECT_RSA_3233 ENDPOINT=/api/lab/submit/" + purpose);
        if (purpose.equals("initial")) {
            return triggerThreat(sessionId, modulus, factor1, factor2, period);
        }
        if (purpose.equals("repeat")) {
            return repeatAttack(sessionId, modulus, factor1, factor2, period);
        }
        consumeAttackSession(sessionId, purpose);
        throw new IllegalArgumentException("Unknown attack purpose.");
    }

    synchronized Map<String, Object> triggerThreat(String sessionId, int modulus, int factor1, int factor2, int period)
            throws Exception {
        requireUnlocked();
        consumeAttackSession(sessionId, "initial");
        if (!validToyEvidence(modulus, factor1, factor2, period)) {
            recordEvent("QUANTUM_THREAT_REJECTED", "", keyVersion, "TEST_EVIDENCE_INVALID");
            throw new IllegalArgumentException("Threat evidence did not match the project's fixed educational RSA target.");
        }
        if ("PQC_ACTIVE".equals(state)) {
            recordEvent("QUANTUM_THREAT", "", keyVersion, "RSA_TEST_ALREADY_REVOKED");
            return map("state", state, "alreadyHealed", true, "keyVersion", keyVersion,
                    "message", "The RSA test path was already revoked; PQC-protected files remain on their active version.");
        }
        if (!"PQC_BASELINE".equals(state)) {
            throw new IllegalStateException("The vault is in " + state + ". Resolve that state before another initial threat transition.");
        }
        long healingStarted = System.nanoTime();
        recordEvent("SUSPICIOUS_ACCESS", "", keyVersion, "AUTHORIZED_CONTROLLED_RSA_TEST_CIPHERTEXT_ACCESS");
        recordEvent("SUSPICIOUS_ACTIVITY", "", keyVersion, "FIXED_PROJECT_RSA_TARGET_EVIDENCE_VALIDATED");
        recordEvent("ATTACK_DETECTED", "", keyVersion, "AUTHORIZED_TOY_RSA_TARGET_3233_FACTORED");
        state = "THREAT_DETECTED";
        persistVaultState();
        recordEvent("SELF_HEALING_STARTED", "", keyVersion, "CONTROLLED_TOY_RSA_EVIDENCE_VALIDATED");
        recordEvent("QUANTUM_THREAT", "", keyVersion, "TOY_RSA_3233_FACTORED_61_X_53");
        state = "RSA_TEST_COMPROMISED";
        persistVaultState();
        recordEvent("RSA_VULNERABILITY_DETECTED", "", keyVersion, "AUTHORIZED_TOY_TARGET_FACTORED");
        state = "RSA_TEST_REVOKED";
        persistVaultState();
        attackSessions.entrySet().removeIf(entry -> entry.getValue().equals("initial"));
        recordEvent("ATTACK_SESSIONS_INVALIDATED", "", keyVersion, "OLD_INITIAL_TEST_SESSIONS_REVOKED");
        recordEvent("RSA_TEST_PATH_REVOKED", "", keyVersion, "INITIAL_TEST_SESSIONS_INVALIDATED_NO_RSA_VAULT_KEY_EXISTS");

        int oldVersion = keyVersion;
        int newVersion = oldVersion + 1;
        List<String> migrated = new ArrayList<>();
        Map<String, Integer> originalVersions = new LinkedHashMap<>();
        for (String id : currentRecordIds()) originalVersions.put(id, currentVersion(id));
        KeyPair oldKem = kemKeys.get(oldVersion);
        KeyPair oldSigning = signingKeys.get(oldVersion);
        try {
            KeyPair nextKem = generateKeyPair("ML-KEM", "ML-KEM-768");
            KeyPair nextSigning = generateKeyPair("ML-DSA", "ML-DSA-65");
            kemKeys.put(newVersion, nextKem);
            signingKeys.put(newVersion, nextSigning);
            keyVersion = newVersion;
            persistKeyBundleFromPassphraseUnavailable();
            recordEvent("NEW_KEY_GENERATED", "", newVersion, "ML_KEM_768_AND_ML_DSA_65");
            recordEvent("NEW_PROTECTION_CREATED", "", newVersion, "ML_KEM_768_AND_ML_DSA_65_ACTIVE_CANDIDATE");
            state = "FILE_MIGRATION";
            persistVaultState();

            for (Map.Entry<String, Integer> record : originalVersions.entrySet()) {
                String id = record.getKey();
                int current = record.getValue();
                Map<String, String> oldMetadata = readMetadata(packageDirectory(id, current));
                byte[] plaintext = decryptAndVerify(id, current, oldMetadata);
                recordEvent("FILE_MIGRATION_STARTED", id, newVersion, "OLD_VERSION_" + current);
                protectVersion(id, newVersion, oldMetadata.get("filename"),
                        oldMetadata.get("contentType"), plaintext, oldMetadata.get("sha256"));
                Map<String, String> migratedMetadata = readMetadata(packageDirectory(id, newVersion));
                decryptAndVerify(id, newVersion, migratedMetadata);
                createBackup(id, newVersion);
                recordEvent("SIGNATURE_RECREATED", id, newVersion, "ML_DSA_65_METADATA_SIGNATURE_VERIFIED");
                recordEvent("FILE_MIGRATED", id, newVersion, "REPROTECTED_RESIGNED_VERIFIED");
                recordEvent("INTEGRITY_VERIFIED", id, newVersion, "MIGRATED_VERSION_SIGNATURE_GCM_TAG_AND_SHA256_VALID");
                migrated.add(id);
            }
            for (String id : migrated) writeRecordPointer(id, newVersion, "ACTIVE");
            kemKeys.remove(oldVersion);
            signingKeys.remove(oldVersion);
            persistKeyBundleFromPassphraseUnavailable();
                recordEvent("KEY_REVOKED", "", newVersion,
                    "OLD_ML_KEM_AND_ML_DSA_VERSION_REMOVED_AFTER_VERIFIED_FILE_MIGRATION");
                recordEvent("OLD_PROTECTION_REVOKED", "", newVersion,
                    "OLD_PQC_KEY_MATERIAL_REMOVED_AFTER_VERIFIED_MIGRATION_RSA_WAS_NOT_USED_FOR_FILES");
            state = "PQC_ACTIVE";
            persistVaultState();
            recordEvent("SELF_HEALING_COMPLETED", "", newVersion,
                    "ALL_FILES_VERIFIED_PQC_ACTIVE_MIGRATION_MS=" + elapsedMillis(healingStarted));
            recordEvent("PERFORMANCE_MIGRATION", "", newVersion,
                    "ELAPSED_MS=" + elapsedMillis(healingStarted) + " MIGRATED_FILES=" + migrated.size());
            return map("state", state, "oldVersion", oldVersion, "keyVersion", newVersion,
                    "migratedFiles", migrated.size(), "recordIds", migrated,
                    "message", "Files were migrated, re-protected, re-signed, and verified before the old key version was removed.");
        } catch (Exception exception) {
            originalVersions.forEach((id, version) -> {
                try { writeRecordPointer(id, version, "ACTIVE"); } catch (IOException ignored) { }
            });
            for (String id : originalVersions.keySet()) {
                try { deleteTree(packageDirectory(id, newVersion)); } catch (IOException ignored) { }
                try { deleteTree(backupRoot.resolve(id).resolve("v" + newVersion)); } catch (IOException ignored) { }
            }
            if (oldKem != null) kemKeys.put(oldVersion, oldKem);
            if (oldSigning != null) signingKeys.put(oldVersion, oldSigning);
            keyVersion = oldVersion;
            kemKeys.remove(newVersion);
            signingKeys.remove(newVersion);
            try { persistKeyBundleFromPassphraseUnavailable(); } catch (Exception ignored) { }
            state = "HEALING_FAILED";
            try { persistVaultState(); } catch (IOException ignored) { }
            try { recordEvent("SELF_HEALING_FAILED", "", oldVersion, exception.getClass().getSimpleName()); }
            catch (IOException ignored) { }
            throw exception;
        }
    }

    synchronized Map<String, Object> repeatAttack(String sessionId, int modulus, int factor1, int factor2, int period)
            throws Exception {
        requireUnlocked();
        consumeAttackSession(sessionId, "repeat");
        if (!validToyEvidence(modulus, factor1, factor2, period)) {
            recordEvent("REPEAT_ATTACK_REJECTED", "", keyVersion, "TEST_EVIDENCE_INVALID");
            throw new IllegalArgumentException("Repeat-attack evidence did not match the fixed educational target.");
        }
        boolean oldPqcKeyRevoked = "PQC_ACTIVE".equals(state) && !kemKeys.containsKey(keyVersion - 1);
        boolean oldTestSessionsInvalidated = "PQC_ACTIVE".equals(state)
            && attackSessions.values().stream().noneMatch("initial"::equals);
        recordEvent("SUSPICIOUS_ACCESS", "", keyVersion, "AUTHORIZED_REPEAT_TOY_RSA_TEST_ACCESS");
        recordEvent("REPEAT_ATTACK", "", keyVersion,
            oldPqcKeyRevoked && oldTestSessionsInvalidated
                ? "INITIAL_RSA_TEST_SESSIONS_INVALIDATED_OLD_PQC_VERSION_REVOKED_OLD_ATTACK_PATH_REJECTED"
                : "CONTROLLED_TOY_FACTORIZATION_ONLY");
        recordEvent("SECOND_ATTACK_REJECTED", "", keyVersion,
            oldPqcKeyRevoked && oldTestSessionsInvalidated
                ? "OLD_RSA_TEST_SESSION_INVALID_AND_OLD_PQC_VERSION_RETIRED"
                : "FIXED_TOY_TARGET_ONLY");
        return map("state", state, "oldRsaTestSessionInvalidated", oldTestSessionsInvalidated,
            "oldPqcKeyVersionRevoked", oldPqcKeyRevoked, "activeProtection", "ML-KEM-768",
                "keyVersion", keyVersion, "factorization", "3233 = 61 x 53",
            "reason", oldPqcKeyRevoked && oldTestSessionsInvalidated
                ? "The repeat only factors the isolated toy RSA modulus. Initial RSA-test sessions were invalidated, and vault files use the active ML-KEM-wrapped AES key; old ML-KEM/ML-DSA key version " + (keyVersion - 1) + " was removed after verified migration."
                        : "The fixed educational RSA target was factored. Complete self-healing before running the post-healing comparison.");
    }

    synchronized List<Map<String, Object>> auditEvents() {
        return new ArrayList<>(events);
    }

    synchronized String answerSecurityQuestion(String question) throws Exception {
        Map<String, Object> context = securityContext();
        String normalized = question.toLowerCase(java.util.Locale.ROOT);
        String stateNow = context.get("vaultState").toString();
        String protection = context.get("activeProtection").toString();
        String healing = context.get("selfHealingStatus").toString();
        String integrity = context.get("integrityStatus").toString();
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> files = (List<Map<String, Object>>) context.get("files");
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> attacks = (List<Map<String, Object>>) context.get("attackHistory");
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> recent = (List<Map<String, Object>>) context.get("recentEvents");

        if (normalized.contains("ml-kem")) return "ML-KEM-768 is the standardized post-quantum key-encapsulation mechanism provided by this JDK. In this vault it establishes a shared secret used to wrap each file's random AES key; it does not encrypt bulk file contents.";
        if (normalized.contains("ml-dsa")) return "ML-DSA-65 is the standardized post-quantum digital-signature algorithm provided by this JDK. The vault signs canonical file metadata and verifies that signature before recovery.";
        if (normalized.contains("aes")) return "AES-256-GCM encrypts each file using a fresh random 256-bit file key and a unique 96-bit nonce. Its authentication tag detects modified ciphertext during recovery.";
        if (normalized.contains("shor")) return "The project uses a fixed toy RSA modulus (3233) and classical period/factor calculations to teach the Shor workflow. It is not a quantum computation, does not attack RSA-2048, and is not a live threat detector.";
        if (normalized.contains("viva") || normalized.contains("project")) return "VaultIQ is a final-year engineering prototype: Java protects real uploaded files with AES-256-GCM, wraps file keys using JDK ML-KEM-768, signs metadata with ML-DSA-65, and verifies recovery. A controlled toy RSA/Shor lesson can trigger audited key rotation and file migration. The network lab is restricted to a configured, certificate-authenticated client.";
        if (normalized.contains("complete security process") || normalized.contains("security process")) return "The backend hashes an uploaded file, encrypts it with AES-256-GCM, wraps the random file key using ML-KEM-768, signs metadata with ML-DSA-65, and stores only the encrypted package. The fixed educational RSA/Shor evidence can start key rotation; files are decrypted only in memory, migrated to the new PQC version, re-signed, verified, and the retired key material is removed. Recovery repeats signature, GCM-tag, length, and SHA-256 checks. Audit events persist the lifecycle.";
        if (normalized.contains("self-healing") || normalized.contains("self healing") || normalized.contains("migration")) {
            if ("COMPLETED".equals(healing)) return "The backend recorded the fixed toy RSA evidence and completed migration: it generated a new ML-KEM/ML-DSA version, re-protected and re-signed the files, verified them, retired the old key version, and persisted SELF_HEALING_COMPLETED. This is a controlled lifecycle demonstration, not an automatically detected real-world quantum attack.";
            return "Self-healing is " + healing + " in the current backend state " + stateNow + ". The system only starts the transition after its fixed educational RSA test evidence is validated.";
        }
        if (normalized.contains("audit") || normalized.contains("event")) {
            StringBuilder summary = new StringBuilder("The backend currently reports ").append(recent.size()).append(" recent audit events. Latest first:");
            for (int i = 0; i < Math.min(5, recent.size()); i++) {
                Map<String, Object> event = recent.get(i);
                summary.append(" ").append(event.get("time")).append(" ").append(event.get("action"))
                        .append(" (result: ").append(event.get("result")).append(");");
            }
            return summary.toString();
        }
        if (normalized.contains("attack") || normalized.contains("rsa") || normalized.contains("threat")) {
            if (normalized.contains("rsa v1") || normalized.contains("rsa key")) return "RSA V1 belongs to the isolated educational RSA test, not to the file-vault encryption. The backend invalidated initial test sessions after validating the fixed N=3233 exercise; file protection used PQC-wrapped AES file keys. Current state: " + stateNow + "; active protection: " + protection + ".";
            if (attacks.isEmpty()) return "No attack or threat event is present in the current persisted audit context. The RSA/Shor teaching simulation is separate from the PQC file-protection path.";
            Map<String, Object> latest = attacks.get(0);
            return "The latest recorded related event is " + latest.get("action") + " at " + latest.get("time")
                    + " (result: " + latest.get("result") + "). This is the controlled toy RSA lab; the vault files use " + protection + ".";
        }
        if (normalized.contains("tamper")) {
            String tamper = context.get("tamperingStatus").toString();
            String restored = context.get("backupRestoreStatus").toString();
            return "NONE".equals(tamper) ? "No TAMPERING_DETECTED event is recorded in the persistent audit log." : "The persistent audit log records tampering evidence: " + tamper + ". Backup restoration evidence: " + ("NONE".equals(restored) ? "not recorded" : restored) + "; current file signature and integrity status: " + context.get("signatureStatus") + " / " + context.get("integrityStatus") + ".";
        }
        if (normalized.contains("recover")) {
            String recovery = context.get("recoveryStatus").toString();
            return "Most recent persisted recovery status: " + recovery + ("NONE".equals(recovery)
                    ? ". No successful recovery is recorded yet. A successful recovery requires signature, GCM tag, length, and SHA-256 checks."
                    : ". The backend records a successful recovery only after signature, GCM tag, length, and SHA-256 checks pass.");
        }
        if (normalized.contains("revok") || normalized.contains("old key") || normalized.contains("rsa v1")) {
            if ("COMPLETED".equals(healing)) return "Self-healing completed after the fixed toy RSA evidence was validated. The initial test session was invalidated; the old PQC key version was retired only after each file was migrated, re-signed, and verified. No RSA key encrypted vault files.";
            return "The current backend state is " + stateNow + ". No completed self-healing transition is recorded yet; check the threat and audit screens for persisted events.";
        }
        if (normalized.contains("safe") || normalized.contains("security status") || normalized.contains("current security")
                || normalized.contains("protection active") || normalized.contains("protection is active")
                || normalized.contains("protection is currently active") || normalized.contains("active protection")) {
            return "Current state: " + stateNow + ". Active protection: " + protection + "; key version " + context.get("activeKeyVersion")
                    + "; self-healing: " + healing + "; signatures: " + context.get("signatureStatus")
                    + "; integrity evidence: " + integrity + ". This status is based on the current backend context, not a claim of production readiness.";
        }
        if (normalized.contains("file") || normalized.contains("integrity") || normalized.contains("signature")) {
            if (files.isEmpty()) return "There are no protected files in the unlocked vault, so there is no file integrity or recovery result to report.";
            Map<String, Object> file = files.get(0);
            return "The latest listed protected file is " + file.get("filename") + " (" + file.get("sizeBytes") + " bytes, key version "
                    + file.get("version") + "; SHA-256 " + file.get("sha256") + "). Its metadata signature is " + file.get("signatureStatus")
                    + " and integrity status is " + file.get("integrityStatus") + ". A recovery is reported only after backend signature, GCM-tag, and SHA-256 checks succeed.";
        }
        return "I can answer from the live vault context about current security, files, attacks, key revocation, audit events, AES-256-GCM, ML-KEM, ML-DSA, Shor's simulation, or the project for a viva. Ask a specific question and I will use the backend's recorded state.";
    }

        synchronized Map<String, Object> securityContext() throws Exception {
        requireUnlocked();
        List<Map<String, Object>> files = new ArrayList<>();
        boolean allSignaturesValid = true;
        boolean anyVerifiedIntegrity = false;
        for (String id : currentRecordIds()) {
            int version = currentVersion(id);
            Map<String, String> metadata = readMetadata(packageDirectory(id, version));
            boolean signatureValid = verifyMetadataSignature(id, version, metadata);
            allSignaturesValid &= signatureValid;
            Map<String, Object> file = map(
                "id", id,
                "filename", metadata.get("filename"),
                "contentType", metadata.get("contentType"),
                "sizeBytes", parseInt(metadata.get("originalSize"), 0),
                "sha256", metadata.get("sha256"),
                "version", version,
                "sha256Prefix", metadata.getOrDefault("sha256", "").substring(0,
                    Math.min(12, metadata.getOrDefault("sha256", "").length())),
                "signatureStatus", signatureValid ? "VALID" : "INVALID",
                "integrityStatus", latestEventFor(id, "INTEGRITY_VERIFIED", version) == null
                    ? "NOT_RECENTLY_RECOVERED" : "VERIFIED");
            files.add(file);
            anyVerifiedIntegrity |= "VERIFIED".equals(file.get("integrityStatus"));
        }
        List<Map<String, Object>> attacks = events.stream()
            .filter(event -> event.get("action").toString().contains("ATTACK")
                || event.get("action").toString().contains("THREAT")
                || event.get("action").toString().contains("RSA_VULNERABILITY"))
            .limit(20).toList();
        List<Map<String, Object>> recent = events.stream().limit(50).toList();
        Map<String, Object> result = map(
            "contextVersion", 1,
            "vaultState", state,
            "activeKeyVersion", keyVersion,
            "activeProtection", "AES-256-GCM with ML-KEM-768 file-key wrapping",
            "signatureAlgorithm", "ML-DSA-65",
            "threatStatus", attacks.isEmpty() ? "NO_ATTACK_EVENT_RECORDED" : "CONTROLLED_TEST_EVENTS_RECORDED",
            "selfHealingStatus", "PQC_ACTIVE".equals(state) ? "COMPLETED" : "NOT_COMPLETED",
            "fileCount", files.size(),
            "signatureStatus", files.isEmpty() ? "NO_FILES" : allSignaturesValid ? "ALL_VALID" : "INVALID_SIGNATURE_PRESENT",
            "integrityStatus", files.isEmpty() ? "NO_FILES" : anyVerifiedIntegrity ? "VERIFIED" : "NO_RECENT_INTEGRITY_VERIFICATION",
            "recoveryStatus", latestAction("FILE_RECOVERED"),
            "tamperingStatus", latestAction("TAMPERING_DETECTED"),
            "backupRestoreStatus", latestAction("BACKUP_RESTORED"),
            "files", files,
            "attackHistory", attacks,
            "recentEvents", recent,
            "simulationBoundary", "RSA/Shor is a fixed toy classical simulation; no live quantum threat detection is implemented.");
        return result;
        }

        private boolean verifyMetadataSignature(String id, int version, Map<String, String> metadata)
            throws Exception {
        KeyPair signingPair = signingKeys.get(parseInt(metadata.get("keyVersion"), -1));
        if (signingPair == null) return false;
        Signature verifier = Signature.getInstance("ML-DSA");
        verifier.initVerify(signingPair.getPublic());
        verifier.update(canonicalMetadata(toProperties(metadata)));
        return verifier.verify(Files.readAllBytes(packageDirectory(id, version).resolve("signature.bin")));
        }

    private Map<String, Object> latestEventFor(String id, String action, int version) {
        return events.stream().filter(event -> id.equals(event.get("record"))
            && action.equals(event.get("action")) && version == ((Number) event.get("version")).intValue())
            .findFirst().orElse(null);
        }

        private String latestAction(String action) {
        return events.stream().filter(event -> action.equals(event.get("action")))
            .map(event -> event.get("result").toString()).findFirst().orElse("NONE");
        }

    synchronized Map<String, Object> protectVersion(String id, int version, String filename,
                                                     String contentType, byte[] plaintext, String fileHash)
            throws Exception {
        KeyPair kemPair = kemKeys.get(version);
        KeyPair signingPair = signingKeys.get(version);
        if (kemPair == null || signingPair == null) throw new GeneralSecurityException("Active PQC key version is unavailable.");
        Path output = packageDirectory(id, version);
        Path staging = output.resolveSibling("v" + version + ".staging");
        deleteTree(staging);
        Files.createDirectories(staging);

        long pqcStart = System.nanoTime();
        KEM.Encapsulated encapsulated = KEM.getInstance("ML-KEM")
                .newEncapsulator(kemPair.getPublic(), RANDOM).encapsulate();
        byte[] wrapSalt = randomBytes(32);
        SecretKey wrappingKey = hkdf(encapsulated.key().getEncoded(), wrapSalt,
                "SelfHealingPQC:file-key-wrap:v1".getBytes(StandardCharsets.UTF_8));
        byte[] fileKeyBytes = randomBytes(32);
        byte[] wrapNonce = randomBytes(12);
        byte[] wrapAad = keyWrapAad(id, version);
        byte[] wrappedFileKey = gcm(Cipher.ENCRYPT_MODE, wrappingKey, wrapNonce, wrapAad, fileKeyBytes);
        double pqcKeyProtectionMillis = elapsedMillis(pqcStart);

        long encryptionStart = System.nanoTime();
        byte[] nonce = randomBytes(12);
        byte[] fileAad = fileAad(id, version, fileHash);
        byte[] ciphertext = gcm(Cipher.ENCRYPT_MODE, new SecretKeySpec(fileKeyBytes, "AES"),
                nonce, fileAad, plaintext);
        double encryptionMillis = elapsedMillis(encryptionStart);
        Arrays.fill(fileKeyBytes, (byte) 0);

        Properties metadata = new Properties();
        metadata.setProperty("id", id);
        metadata.setProperty("version", Integer.toString(version));
        metadata.setProperty("filename", filename);
        metadata.setProperty("contentType", contentType);
        metadata.setProperty("originalSize", Integer.toString(plaintext.length));
        metadata.setProperty("sha256", fileHash);
        metadata.setProperty("keyVersion", Integer.toString(version));
        metadata.setProperty("kem", "ML-KEM-768");
        metadata.setProperty("encryption", "AES-256-GCM");
        metadata.setProperty("signature", "ML-DSA-65");
        metadata.setProperty("createdAt", Instant.now().toString());
        byte[] canonical = canonicalMetadata(metadata);
        long signatureStart = System.nanoTime();
        Signature signer = Signature.getInstance("ML-DSA");
        signer.initSign(signingPair.getPrivate(), RANDOM);
        signer.update(canonical);
        byte[] signature = signer.sign();
        double signatureMillis = elapsedMillis(signatureStart);

        Files.write(staging.resolve("ciphertext.bin"), ciphertext);
        Files.write(staging.resolve("nonce.bin"), nonce);
        Files.write(staging.resolve("file-key-wrap.bin"), wrappedFileKey);
        Files.write(staging.resolve("wrap-nonce.bin"), wrapNonce);
        Files.write(staging.resolve("wrap-salt.bin"), wrapSalt);
        Files.write(staging.resolve("encapsulation.bin"), encapsulated.encapsulation());
        Files.write(staging.resolve("signature.bin"), signature);
        storeProperties(staging.resolve("metadata.properties"), metadata);
        replaceDirectory(staging, output);
        Map<String, Object> result = details(id, metadata, ciphertext.length, nonce, wrapNonce,
                encapsulated.encapsulation(), signature, canonical);
        result.put("performanceMs", map(
                "kemAndKeyWrap", pqcKeyProtectionMillis,
                "aes256GcmEncryption", encryptionMillis,
                "mldsa65Signing", signatureMillis));
        return result;
    }

    private byte[] decryptAndVerify(String id, int version, Map<String, String> metadata)
            throws Exception {
        Path packageDir = packageDirectory(id, version);
        if (!id.equals(metadata.get("id")) || version != parseInt(metadata.get("version"), -1)) {
            throw new SecurityException("Protected metadata does not match its record/version.");
        }
        KeyPair kemPair = kemKeys.get(parseInt(metadata.get("keyVersion"), -1));
        KeyPair signingPair = signingKeys.get(parseInt(metadata.get("keyVersion"), -1));
        if (kemPair == null || signingPair == null) throw new SecurityException("The key version is revoked or unavailable.");

        Properties values = new Properties();
        metadata.forEach(values::setProperty);
        Signature verifier = Signature.getInstance("ML-DSA");
        verifier.initVerify(signingPair.getPublic());
        verifier.update(canonicalMetadata(values));
        if (!verifier.verify(Files.readAllBytes(packageDir.resolve("signature.bin")))) {
            throw new SecurityException("ML-DSA metadata signature verification failed.");
        }

        SecretKey sharedSecret = KEM.getInstance("ML-KEM").newDecapsulator(kemPair.getPrivate())
                .decapsulate(Files.readAllBytes(packageDir.resolve("encapsulation.bin")));
        SecretKey wrappingKey = hkdf(sharedSecret.getEncoded(),
                Files.readAllBytes(packageDir.resolve("wrap-salt.bin")),
                "SelfHealingPQC:file-key-wrap:v1".getBytes(StandardCharsets.UTF_8));
        byte[] fileKeyBytes = gcm(Cipher.DECRYPT_MODE, wrappingKey,
                Files.readAllBytes(packageDir.resolve("wrap-nonce.bin")), keyWrapAad(id, version),
                Files.readAllBytes(packageDir.resolve("file-key-wrap.bin")));
        if (fileKeyBytes.length != 32) throw new SecurityException("Unwrapped file key has an invalid length.");
        byte[] plaintext;
        try {
            plaintext = gcm(Cipher.DECRYPT_MODE, new SecretKeySpec(fileKeyBytes, "AES"),
                    Files.readAllBytes(packageDir.resolve("nonce.bin")),
                    fileAad(id, version, metadata.get("sha256")),
                    Files.readAllBytes(packageDir.resolve("ciphertext.bin")));
        } finally {
            Arrays.fill(fileKeyBytes, (byte) 0);
        }
        if (plaintext.length != parseInt(metadata.get("originalSize"), -1)) {
            throw new SecurityException("Recovered file length does not match signed metadata.");
        }
        if (!MessageDigest.isEqual(sha256(plaintext), HexFormat.of().parseHex(metadata.get("sha256")))) {
            throw new SecurityException("Recovered file SHA-256 does not match signed metadata.");
        }
        return plaintext;
    }

    private Map<String, Object> readDetails(String id) throws Exception {
        int version = currentVersion(id);
        Path dir = packageDirectory(id, version);
        Map<String, String> metadata = readMetadata(dir);
        byte[] ciphertext = Files.readAllBytes(dir.resolve("ciphertext.bin"));
        byte[] tag = ciphertext.length >= 16
            ? Arrays.copyOfRange(ciphertext, ciphertext.length - 16, ciphertext.length) : new byte[0];
        byte[] canonical = canonicalMetadata(toProperties(metadata));
        KeyPair signingPair = signingKeys.get(version);
        Signature verifier = Signature.getInstance("ML-DSA");
        verifier.initVerify(signingPair.getPublic());
        verifier.update(canonical);
        boolean signatureValid = verifier.verify(Files.readAllBytes(dir.resolve("signature.bin")));
        return map(
                "id", id,
                "filename", metadata.get("filename"),
                "contentType", metadata.get("contentType"),
                "originalSize", parseInt(metadata.get("originalSize"), 0),
                "sha256", metadata.get("sha256"),
                "version", version,
                "keyVersion", parseInt(metadata.get("keyVersion"), version),
                "createdAt", metadata.get("createdAt"),
                "state", readRecordState(id),
                "ciphertextBytes", ciphertext.length,
                "nonce", encode(Files.readAllBytes(dir.resolve("nonce.bin"))),
                "authenticationTag", encode(tag),
                "ciphertextPreview", encode(Arrays.copyOf(ciphertext, Math.min(Math.max(0, ciphertext.length - 16), 48))),
                "encapsulation", encode(Files.readAllBytes(dir.resolve("encapsulation.bin"))),
                "wrappedFileKey", encode(Files.readAllBytes(dir.resolve("file-key-wrap.bin"))),
                "signature", encode(Files.readAllBytes(dir.resolve("signature.bin"))),
                "signatureBytes", Files.size(dir.resolve("signature.bin")),
                "canonicalMetadata", new String(canonical, StandardCharsets.UTF_8),
                "metadataDigest", sha256Hex(canonical),
                "signatureValid", signatureValid,
                "protection", metadata.get("encryption"),
                "kem", metadata.get("kem"),
                "signatureAlgorithm", metadata.get("signature"),
                "integrityStatus", latestEventFor(id, "INTEGRITY_VERIFIED", version) == null
                        ? "NOT_RECENTLY_VERIFIED" : "VERIFIED",
                "status", readRecordState(id));
    }

    private Map<String, Object> details(String id, Properties metadata, int cipherBytes,
                                        byte[] nonce, byte[] wrapNonce, byte[] encapsulation,
                                        byte[] signature, byte[] canonical) throws Exception {
                        byte[] ciphertext = Files.readAllBytes(packageDirectory(id,
                            Integer.parseInt(metadata.getProperty("version"))).resolve("ciphertext.bin"));
                        byte[] tag = ciphertext.length >= 16
                            ? Arrays.copyOfRange(ciphertext, ciphertext.length - 16, ciphertext.length) : new byte[0];
        return map(
                "id", id,
                "filename", metadata.getProperty("filename"),
                "contentType", metadata.getProperty("contentType"),
                "originalSize", Integer.parseInt(metadata.getProperty("originalSize")),
                "sha256", metadata.getProperty("sha256"),
                "version", Integer.parseInt(metadata.getProperty("version")),
                "keyVersion", Integer.parseInt(metadata.getProperty("keyVersion")),
                "createdAt", metadata.getProperty("createdAt"),
                "ciphertextBytes", cipherBytes,
                "nonce", encode(nonce),
                "keyWrapNonce", encode(wrapNonce),
                "authenticationTag", encode(tag),
                "ciphertextPreview", encode(Arrays.copyOf(ciphertext, Math.min(Math.max(0, ciphertext.length - 16), 48))),
                "encapsulation", encode(encapsulation),
                "wrappedFileKey", encode(FilesSafeRead(packageDirectory(id, Integer.parseInt(metadata.getProperty("version")))
                        .resolve("file-key-wrap.bin"))),
                "signature", encode(signature),
                "signatureBytes", signature.length,
                "canonicalMetadata", new String(canonical, StandardCharsets.UTF_8),
                "metadataDigest", sha256Hex(canonical),
                "signatureValid", true,
                "protection", metadata.getProperty("encryption"),
                "kem", metadata.getProperty("kem"),
                "signatureAlgorithm", metadata.getProperty("signature"));
    }

    private void loadKeyBundle(char[] passphrase) throws Exception {
        byte[] bundle = Files.readAllBytes(bundleFile);
        try (DataInputStream input = new DataInputStream(new ByteArrayInputStream(bundle))) {
            int format = input.readInt();
            if (format != 1) throw new IOException("Unknown vault key-bundle format.");
            byte[] salt = readBytes(input, 64);
            bundleSalt = salt.clone();
            byte[] nonce = readBytes(input, 32);
            byte[] sealed = readBytes(input, 64 * 1024);
                SecretKey candidateWrappingKey = passwordKey(passphrase, salt);
                byte[] plain = gcm(Cipher.DECRYPT_MODE, candidateWrappingKey, nonce,
                    "SelfHealingPQC:vault-key-bundle:v1".getBytes(StandardCharsets.UTF_8), sealed);
            try (DataInputStream keys = new DataInputStream(new ByteArrayInputStream(plain))) {
                keyVersion = keys.readInt();
                int count = keys.readInt();
                if (count < 1 || count > 16) throw new IOException("Vault key-version count is invalid.");
                kemKeys.clear();
                signingKeys.clear();
                for (int i = 0; i < count; i++) {
                    int version = keys.readInt();
                    kemKeys.put(version, readKeyPair(keys, "ML-KEM"));
                    signingKeys.put(version, readKeyPair(keys, "ML-DSA"));
                }
            }
            Arrays.fill(plain, (byte) 0);
            bundleWrappingKey = candidateWrappingKey;
        } catch (AEADBadTagException exception) {
            throw new IllegalArgumentException("Vault could not be unlocked. Check the passphrase.");
        } finally {
            Arrays.fill(passphrase, '\0');
        }
        if (!kemKeys.containsKey(keyVersion) || !signingKeys.containsKey(keyVersion)) {
            throw new IOException("Active vault key version is missing from the encrypted key bundle.");
        }
    }

    private void persistKeyBundle(char[] passphrase) throws Exception {
        byte[] plain;
        try (ByteArrayOutputStream bytes = new ByteArrayOutputStream();
             DataOutputStream output = new DataOutputStream(bytes)) {
            output.writeInt(keyVersion);
            output.writeInt(kemKeys.size());
            for (int version : kemKeys.keySet()) {
                output.writeInt(version);
                writeKeyPair(output, kemKeys.get(version));
                writeKeyPair(output, signingKeys.get(version));
            }
            plain = bytes.toByteArray();
        }
        byte[] nextSalt = randomBytes(16);
        byte[] nonce = randomBytes(12);
        SecretKey nextWrappingKey = passwordKey(passphrase, nextSalt);
        byte[] sealed = gcm(Cipher.ENCRYPT_MODE, nextWrappingKey, nonce,
                "SelfHealingPQC:vault-key-bundle:v1".getBytes(StandardCharsets.UTF_8), plain);
        Arrays.fill(plain, (byte) 0);
        Path temporary = bundleFile.resolveSibling("keys.bundle.tmp");
        try (DataOutputStream output = new DataOutputStream(Files.newOutputStream(temporary))) {
            output.writeInt(1);
            writeBytes(output, nextSalt);
            writeBytes(output, nonce);
            writeBytes(output, sealed);
        }
        atomicMove(temporary, bundleFile);
        bundleSalt = nextSalt;
        bundleWrappingKey = nextWrappingKey;
        Arrays.fill(passphrase, '\0');
    }

    private SecretKey passwordKey(char[] passphrase, byte[] salt) throws GeneralSecurityException {
        PBEKeySpec spec = new PBEKeySpec(passphrase, salt, KEY_BUNDLE_ITERATIONS, 256);
        try {
            return new SecretKeySpec(SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
                    .generateSecret(spec).getEncoded(), "AES");
        } finally {
            spec.clearPassword();
        }
    }

    private void persistKeyBundleFromPassphraseUnavailable() throws Exception {
        if (bundleWrappingKey == null) throw new IllegalStateException("Vault key bundle is locked.");
        byte[] plain;
        try (ByteArrayOutputStream bytes = new ByteArrayOutputStream();
             DataOutputStream output = new DataOutputStream(bytes)) {
            output.writeInt(keyVersion);
            output.writeInt(kemKeys.size());
            for (int version : kemKeys.keySet()) {
                output.writeInt(version);
                writeKeyPair(output, kemKeys.get(version));
                writeKeyPair(output, signingKeys.get(version));
            }
            plain = bytes.toByteArray();
        }
        if (bundleSalt == null || bundleWrappingKey == null) {
            throw new IllegalStateException("Vault key bundle is locked.");
        }
        byte[] nonce = randomBytes(12);
        byte[] sealed = gcm(Cipher.ENCRYPT_MODE, bundleWrappingKey, nonce,
                "SelfHealingPQC:vault-key-bundle:v1".getBytes(StandardCharsets.UTF_8), plain);
        Arrays.fill(plain, (byte) 0);
        Path temporary = bundleFile.resolveSibling("keys.bundle.tmp");
        try (DataOutputStream output = new DataOutputStream(Files.newOutputStream(temporary))) {
            output.writeInt(1);
            writeBytes(output, bundleSalt);
            writeBytes(output, nonce);
            writeBytes(output, sealed);
        }
        atomicMove(temporary, bundleFile);
    }

    private byte[] canonicalMetadata(Properties metadata) throws IOException {
        String[] keys = {"id", "version", "filename", "contentType", "originalSize", "sha256",
            "keyVersion", "kem", "encryption", "signature", "createdAt"};
        StringBuilder canonical = new StringBuilder("SELF-HEALING-PQC-VAULT-METADATA-V1\n");
        for (String key : keys) {
            String value = metadata.getProperty(key, "");
            canonical.append(key).append(':')
                .append(value.getBytes(StandardCharsets.UTF_8).length)
                .append(':').append(value).append('\n');
        }
        return canonical.toString().getBytes(StandardCharsets.UTF_8);
    }

    private SecretKey hkdf(byte[] inputKey, byte[] salt, byte[] info) throws GeneralSecurityException {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(salt, "HmacSHA256"));
        byte[] pseudorandomKey = mac.doFinal(inputKey);
        mac.init(new SecretKeySpec(pseudorandomKey, "HmacSHA256"));
        mac.update(info);
        mac.update((byte) 1);
        byte[] output = mac.doFinal();
        Arrays.fill(pseudorandomKey, (byte) 0);
        return new SecretKeySpec(Arrays.copyOf(output, 32), "AES");
    }

    private byte[] gcm(int mode, SecretKey key, byte[] nonce, byte[] aad, byte[] input)
            throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(mode, key, new GCMParameterSpec(128, nonce));
        cipher.updateAAD(aad);
        return cipher.doFinal(input);
    }

    private byte[] keyWrapAad(String id, int version) {
        return ("vault-key:" + id + ":" + version).getBytes(StandardCharsets.UTF_8);
    }

    private byte[] fileAad(String id, int version, String hash) {
        return ("vault-file:" + id + ":" + version + ":" + hash).getBytes(StandardCharsets.UTF_8);
    }

    private void createBackup(String id, int version) throws IOException {
        Path source = packageDirectory(id, version);
        Path destination = backupRoot.resolve(id).resolve("v" + version);
        deleteTree(destination);
        Files.createDirectories(destination.getParent());
        copyTree(source, destination);
    }

    private void restoreBackup(String id, int version) throws IOException {
        Path backup = backupRoot.resolve(id).resolve("v" + version);
        if (!Files.isDirectory(backup)) throw new IOException("No verified protected backup exists for this version.");
        Path staging = packageDirectory(id, version).resolveSibling("v" + version + ".restore");
        deleteTree(staging);
        copyTree(backup, staging);
        replaceDirectory(staging, packageDirectory(id, version));
    }

    private void copyTree(Path source, Path destination) throws IOException {
        try (var paths = Files.walk(source)) {
            for (Path path : paths.toList()) {
                Path target = destination.resolve(source.relativize(path));
                if (Files.isDirectory(path)) Files.createDirectories(target);
                else Files.copy(path, target, StandardCopyOption.REPLACE_EXISTING);
            }
        }
    }

    private void replaceDirectory(Path staging, Path target) throws IOException {
        Path previous = target.resolveSibling(target.getFileName() + ".previous");
        deleteTree(previous);
        if (Files.exists(target)) atomicMove(target, previous);
        try {
            atomicMove(staging, target);
            deleteTree(previous);
        } catch (IOException exception) {
            if (!Files.exists(target) && Files.exists(previous)) atomicMove(previous, target);
            throw exception;
        }
    }

    private void writeRecordPointer(String id, int version, String status) throws IOException {
        Properties properties = new Properties();
        properties.setProperty("id", id);
        properties.setProperty("currentVersion", Integer.toString(version));
        properties.setProperty("status", status);
        properties.setProperty("updatedAt", Instant.now().toString());
        storeProperties(recordDirectory(id).resolve("record.properties"), properties);
    }

    private int currentVersion(String id) throws IOException {
        Properties properties = loadProperties(recordDirectory(id).resolve("record.properties"));
        return parseInt(properties.getProperty("currentVersion"), -1);
    }

    private String readRecordState(String id) throws IOException {
        return loadProperties(recordDirectory(id).resolve("record.properties")).getProperty("status", "UNKNOWN");
    }

    private List<String> currentRecordIds() {
        try (var directories = Files.list(recordsRoot)) {
            return directories.filter(Files::isDirectory)
                    .map(path -> path.getFileName().toString())
                    .filter(name -> name.matches("[0-9a-f-]{36}"))
                    .filter(name -> Files.exists(recordDirectory(name).resolve("record.properties")))
                    .toList();
        } catch (IOException exception) {
            return List.of();
        }
    }

    private Path recordDirectory(String id) {
        return recordsRoot.resolve(id).normalize();
    }

    private Path packageDirectory(String id, int version) {
        return recordDirectory(id).resolve("v" + version);
    }

    private Map<String, String> readMetadata(Path dir) throws IOException {
        Properties properties = loadProperties(dir.resolve("metadata.properties"));
        Map<String, String> result = new LinkedHashMap<>();
        for (String key : properties.stringPropertyNames()) result.put(key, properties.getProperty(key));
        return result;
    }

    private Properties toProperties(Map<String, String> values) {
        Properties result = new Properties();
        values.forEach(result::setProperty);
        return result;
    }

    private void loadVaultState() throws IOException {
        Properties properties = loadProperties(vaultPropertiesFile);
        keyVersion = parseInt(properties.getProperty("keyVersion"), 0);
        state = properties.getProperty("state", "PQC_BASELINE");
    }

    private void persistVaultState() throws IOException {
        Properties properties = new Properties();
        properties.setProperty("keyVersion", Integer.toString(keyVersion));
        properties.setProperty("state", state);
        properties.setProperty("updatedAt", Instant.now().toString());
        storeProperties(vaultPropertiesFile, properties);
    }

    private void loadEvents() throws IOException {
        if (!Files.exists(auditFile)) return;
        List<String> lines = Files.readAllLines(auditFile, StandardCharsets.UTF_8);
        for (int i = Math.max(0, lines.size() - 500); i < lines.size(); i++) {
            try {
                String[] fields = lines.get(i).split("\\t", -1);
                if (fields.length != 5) continue;
                Map<String, Object> event = auditEvent(fields[0], fields[1], fields[2],
                        parseInt(fields[3], 0), fields[4]);
                events.add(0, event);
            } catch (RuntimeException exception) {
                // Ignore one malformed event without preventing vault unlock.
            }
        }
    }

    private void recordEvent(String action, String id, int version, String result) throws IOException {
        Map<String, Object> event = auditEvent(Instant.now().toString(), action, id, version, result);
        String line = event.get("time") + "\t" + action + "\t" + id + "\t" + version + "\t" + result;
        Files.writeString(auditFile, line + System.lineSeparator(), StandardCharsets.UTF_8,
                java.nio.file.StandardOpenOption.CREATE, java.nio.file.StandardOpenOption.APPEND);
        events.add(0, event);
        while (events.size() > 500) events.remove(events.size() - 1);
    }

    private Map<String, Object> auditEvent(String time, String action, String id, int version, String result) {
        String status = action.contains("REJECTED") || action.contains("FAILED") ? "REJECTED"
                : action.contains("DETECTED") || action.contains("COMPROMISED") ? "DETECTED"
                : action.contains("VERIFIED") || action.contains("COMPLETED") || action.contains("RESTORED") ? "VERIFIED"
                : "RECORDED";
        return map("time", time, "action", action, "record", id, "version", version,
                "result", result, "source", auditValue(result, "SOURCE"),
                "destination", auditValue(result, "DESTINATION"),
                "target", auditValue(result, "TARGET"), "endpoint", auditValue(result, "ENDPOINT"),
                "status", status);
    }

    private String auditValue(String result, String key) {
        String prefix = key + "=";
        for (String part : result.split("\\s+")) if (part.startsWith(prefix)) return part.substring(prefix.length());
        return "";
    }

    private String safeAuditValue(String value) {
        if (value == null || value.isBlank()) return "UNKNOWN";
        return value.replace('\t', '_').replace('\r', '_').replace('\n', '_');
    }

    private Properties loadProperties(Path path) throws IOException {
        Properties properties = new Properties();
        if (Files.exists(path)) {
            try (var input = Files.newInputStream(path)) { properties.load(input); }
        }
        return properties;
    }

    private void storeProperties(Path path, Properties properties) throws IOException {
        Files.createDirectories(path.getParent());
        Path temporary = path.resolveSibling(path.getFileName() + ".tmp");
        try (var output = Files.newOutputStream(temporary)) { properties.store(output, null); }
        atomicMove(temporary, path);
    }

    private void writeKeyPair(DataOutputStream output, KeyPair pair) throws IOException {
        writeBytes(output, pair.getPrivate().getEncoded());
        writeBytes(output, pair.getPublic().getEncoded());
    }

    private KeyPair readKeyPair(DataInputStream input, String algorithm) throws Exception {
        byte[] privateBytes = readBytes(input, 32 * 1024);
        byte[] publicBytes = readBytes(input, 32 * 1024);
        KeyFactory factory = KeyFactory.getInstance(algorithm);
        PrivateKey privateKey = factory.generatePrivate(new PKCS8EncodedKeySpec(privateBytes));
        PublicKey publicKey = factory.generatePublic(new X509EncodedKeySpec(publicBytes));
        return new KeyPair(publicKey, privateKey);
    }

    private static void writeBytes(DataOutputStream output, byte[] bytes) throws IOException {
        output.writeInt(bytes.length);
        output.write(bytes);
    }

    private static byte[] readBytes(DataInputStream input, int maximum) throws IOException {
        int length = input.readInt();
        if (length < 0 || length > maximum) throw new IOException("Encrypted key bundle field has an invalid size.");
        return input.readNBytes(length);
    }

    private KeyPair generateKeyPair(String algorithm, String parameter) throws GeneralSecurityException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance(algorithm);
        generator.initialize(new NamedParameterSpec(parameter), RANDOM);
        return generator.generateKeyPair();
    }

    private static byte[] randomBytes(int size) {
        byte[] value = new byte[size];
        RANDOM.nextBytes(value);
        return value;
    }

    private static byte[] sha256(byte[] value) throws GeneralSecurityException {
        return MessageDigest.getInstance("SHA-256").digest(value);
    }

    private static String sha256Hex(byte[] value) throws GeneralSecurityException {
        return HexFormat.of().formatHex(sha256(value));
    }

    private static double elapsedMillis(long startedNanos) {
        return Math.round((System.nanoTime() - startedNanos) / 1_000_000.0 * 1000.0) / 1000.0;
    }

    private static void atomicMove(Path source, Path target) throws IOException {
        try {
            Files.move(source, target, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
        } catch (AtomicMoveNotSupportedException exception) {
            Files.move(source, target, StandardCopyOption.REPLACE_EXISTING);
        }
    }

    private static void deleteTree(Path path) throws IOException {
        if (!Files.exists(path)) return;
        try (var paths = Files.walk(path)) {
            for (Path item : paths.sorted(Comparator.reverseOrder()).toList()) Files.deleteIfExists(item);
        }
    }

    private String validateId(String id) {
        if (id == null || !id.matches("[0-9a-f-]{36}")) throw new IllegalArgumentException("File record ID is invalid.");
        return id;
    }

    private int parseInt(String value, int fallback) {
        try { return Integer.parseInt(value); }
        catch (RuntimeException exception) { return fallback; }
    }

    private void requireUnlocked() {
        if (!unlocked) throw new IllegalStateException("Unlock the vault before using file operations.");
    }

    private boolean validToyEvidence(int modulus, int factor1, int factor2, int reportedPeriod) {
        if (modulus != 3233 || reportedPeriod != 260) return false;
        int order = 1;
        while (order <= modulus && modularExponentiation(3, order, modulus) != 1) order++;
        if (order != reportedPeriod || (order & 1) != 0) return false;
        int halfPower = modularExponentiation(3, order / 2, modulus);
        int recovered1 = gcd(halfPower - 1, modulus);
        int recovered2 = gcd(halfPower + 1, modulus);
        return recovered1 > 1 && recovered2 > 1
                && recovered1 * recovered2 == modulus
                && ((factor1 == recovered1 && factor2 == recovered2)
                    || (factor1 == recovered2 && factor2 == recovered1));
    }

    private int modularExponentiation(int base, int exponent, int modulus) {
        return BigInteger.valueOf(base).modPow(BigInteger.valueOf(exponent), BigInteger.valueOf(modulus)).intValue();
    }

    private int gcd(int first, int second) {
        return BigInteger.valueOf(first).gcd(BigInteger.valueOf(second)).intValue();
    }

    private void consumeAttackSession(String sessionId, String expectedPurpose) throws IOException {
        String actualPurpose = attackSessions.remove(sessionId);
        if (!expectedPurpose.equals(actualPurpose)) {
            recordEvent("CONTROLLED_ATTACK_SESSION_REJECTED", "", keyVersion,
                    "MISSING_EXPIRED_OR_ALREADY_CONSUMED_" + expectedPurpose.toUpperCase(java.util.Locale.ROOT));
            throw new IllegalArgumentException("This attack session is expired, already used, or belongs to another workflow. Return to the vault and start an authorized test.");
        }
    }

    private static String encode(byte[] value) { return Base64.getEncoder().encodeToString(value); }

    private static Map<String, Object> map(Object... pairs) {
        Map<String, Object> result = new LinkedHashMap<>();
        for (int i = 0; i < pairs.length; i += 2) result.put((String) pairs[i], pairs[i + 1]);
        return result;
    }

    private byte[] FilesSafeRead(Path path) {
        try { return Files.readAllBytes(path); }
        catch (IOException exception) { throw new IllegalStateException(exception); }
    }

    record DownloadResult(String filename, String contentType, byte[] bytes, Map<String, String> metadata) { }
}
