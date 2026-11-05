import assert from "node:assert/strict";
import { spawn, execFileSync } from "node:child_process";
import { createServer } from "node:net";
import { existsSync } from "node:fs";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { setTimeout as delay } from "node:timers/promises";

const project = resolve(fileURLToPath(new URL("..", import.meta.url)));
const passphrase = "pqc-acceptance-test-passphrase-2026";
const rotatedPassphrase = "pqc-acceptance-rotated-passphrase-2026";
const root = await mkdtemp(join(tmpdir(), "pqc-vault-acceptance-"));
const jdkBin = process.env.JAVA_HOME && existsSync(join(process.env.JAVA_HOME, "bin", "javac.exe"))
    ? join(process.env.JAVA_HOME, "bin")
    : process.env.PATH.split(";").find((entry) => existsSync(join(entry, "javac.exe")));
if (!jdkBin) throw new Error("JDK compiler was not found. Add the JDK bin directory to PATH.");
const javaExecutable = join(jdkBin, "java.exe");
const javacExecutable = join(jdkBin, "javac.exe");
let serverProcess;
let sessionCookie = "";

async function authorizedFetch(url, options = {}) {
    const headers = new Headers(options.headers || {});
    if (sessionCookie) headers.set("Cookie", sessionCookie);
    const response = await fetch(url, { ...options, headers });
    const setCookie = response.headers.get("set-cookie");
    if (setCookie) sessionCookie = setCookie.split(";", 1)[0];
    return response;
}

async function freePort() {
    return new Promise((resolvePort, reject) => {
        const probe = createServer();
        probe.once("error", reject);
        probe.listen(0, "127.0.0.1", () => {
            const address = probe.address();
            probe.close(() => resolvePort(address.port));
        });
    });
}

async function startServer(port) {
    let output = "";
    const child = spawn(javaExecutable, [`-Dserver.port=${port}`, `-Dvault.root=${root}`, "-cp", "backend", "Server"], {
        cwd: project,
        stdio: ["ignore", "pipe", "pipe"]
    });
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk) => { output += chunk; });
    child.stderr.on("data", (chunk) => { output += chunk; });
    const base = `http://127.0.0.1:${port}`;
    const deadline = Date.now() + 15_000;
    while (Date.now() < deadline) {
        if (child.exitCode !== null) throw new Error(`Server exited early:\n${output}`);
        try {
            const response = await fetch(`${base}/api/vault/status`);
            if (response.ok) {
                await response.body?.cancel();
                return { child, base };
            }
        } catch { }
        await delay(100);
    }
    child.kill();
    throw new Error(`Server did not become ready:\n${output}`);
}

async function stopServer(child) {
    if (!child || child.exitCode !== null) return;
    child.kill();
    await Promise.race([
        new Promise((resolveExit) => child.once("exit", resolveExit)),
        delay(3000)
    ]);
}

async function jsonRequest(base, path, { method = "GET", body, headers } = {}) {
    const response = await authorizedFetch(`${base}${path}`, { method, body, headers });
    const result = await response.json();
    return { response, result };
}

try {
    execFileSync(javacExecutable, ["backend/Server.java", "backend/VaultService.java"], {
        cwd: project,
        stdio: "inherit"
    });
    const port = await freePort();
    ({ child: serverProcess } = await startServer(port));
    const base = `http://127.0.0.1:${port}`;

    let { result: status } = await jsonRequest(base, "/api/vault/status");
    assert.equal(status.unlocked, false, "Fresh vault must start locked");
    const denied = await jsonRequest(base, "/api/vault/files");
    assert.equal(denied.response.status, 401, "Vault data must require an authenticated browser session");
    let opened = await jsonRequest(base, "/api/vault/register", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ username: "acceptance-user", password: passphrase })
    });
    assert.equal(opened.response.ok, true, JSON.stringify(opened.result));
    assert.equal(opened.result.unlocked, true);

    const pqcTest = await jsonRequest(base, "/api/vault/pqc-self-test", { method: "POST" });
    assert.equal(pqcTest.response.ok, true, JSON.stringify(pqcTest.result));
    assert.equal(pqcTest.result.decapsulationMatches, true);
    assert.equal(pqcTest.result.signatureValid, true);
    assert.ok(pqcTest.result.encapsulationBytes > 0);

    const original = Uint8Array.from({ length: 8193 }, (_, index) => (index * 37) & 0xff);
    const form = new FormData();
    form.append("file", new Blob([original], { type: "application/octet-stream" }), "acceptance-payload.bin");
    const uploadResponse = await authorizedFetch(`${base}/api/vault/upload`, { method: "POST", body: form });
    const uploaded = await uploadResponse.json();
    assert.equal(uploadResponse.status, 201, JSON.stringify(uploaded));
    const browserDigest = [...new Uint8Array(await crypto.subtle.digest("SHA-256", original))]
        .map((byte) => byte.toString(16).padStart(2, "0")).join("");
    assert.equal(uploaded.sha256, browserDigest, "Independent SHA-256 values must match");
    assert.equal(uploaded.signatureAlgorithm, "ML-DSA-65");
    assert.equal(uploaded.signatureValid, true);

    let { result: details } = await jsonRequest(base, `/api/vault/files/${uploaded.id}`);
    assert.equal(details.protection, "AES-256-GCM");
    assert.equal(details.kem, "ML-KEM-768");
    assert.equal(Buffer.from(details.authenticationTag, "base64").length, 16);
    assert.ok(details.canonicalMetadata.includes(uploaded.sha256));

    let recoveredResponse = await authorizedFetch(`${base}/api/vault/files/${uploaded.id}/download`);
    assert.equal(recoveredResponse.ok, true);
    assert.deepEqual(new Uint8Array(await recoveredResponse.arrayBuffer()), original);

    let tampered = await jsonRequest(base, `/api/vault/files/${uploaded.id}/tamper`, { method: "POST" });
    assert.equal(tampered.response.ok, true, JSON.stringify(tampered.result));
    assert.equal(tampered.result.status, "BACKUP_RESTORED_AND_VERIFIED");
    recoveredResponse = await authorizedFetch(`${base}/api/vault/files/${uploaded.id}/download`);
    assert.deepEqual(new Uint8Array(await recoveredResponse.arrayBuffer()), original);

    let issued = await jsonRequest(base, "/api/vault/attack-session", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ purpose: "initial" })
    });
    assert.equal(issued.response.status, 201);
    const sessionId = issued.result.sessionId;
    let threat = await jsonRequest(base, "/api/vault/threat", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ sessionId, modulus: "3233", factor1: "61", factor2: "53", period: "260" })
    });
    assert.equal(threat.response.ok, true, JSON.stringify(threat.result));
    assert.equal(threat.result.state, "PQC_ACTIVE");
    assert.equal(threat.result.oldVersion, 1);
    assert.equal(threat.result.keyVersion, 2);
    assert.equal(threat.result.migratedFiles, 1);

    let replay = await jsonRequest(base, "/api/vault/threat", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ sessionId, modulus: "3233", factor1: "61", factor2: "53", period: "260" })
    });
    assert.equal(replay.response.ok, false, "An attack session must be single-use");

    details = (await jsonRequest(base, `/api/vault/files/${uploaded.id}`)).result;
    assert.equal(details.version, 2);
    assert.equal(details.integrityStatus, "VERIFIED", "Migrated version must carry integrity verification evidence");
    assert.equal(details.signatureValid, true, "Migrated metadata must be re-signed");
    recoveredResponse = await authorizedFetch(`${base}/api/vault/files/${uploaded.id}/download`);
    assert.deepEqual(new Uint8Array(await recoveredResponse.arrayBuffer()), original);

    issued = await jsonRequest(base, "/api/vault/attack-session", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ purpose: "repeat" })
    });
    assert.equal(issued.response.status, 201);
    const repeat = await jsonRequest(base, "/api/vault/repeat-attack", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ sessionId: issued.result.sessionId, modulus: "3233", factor1: "61", factor2: "53", period: "260" })
    });
    assert.equal(repeat.response.ok, true, JSON.stringify(repeat.result));
    assert.equal(repeat.result.oldRsaTestSessionInvalidated, true);
    assert.equal(repeat.result.oldPqcKeyVersionRevoked, true);
    assert.match(repeat.result.reason, /toy RSA modulus/i);

    const audit = await jsonRequest(base, "/api/vault/audit");
    const actions = audit.result.events.map((event) => event.action);
    for (const action of ["ACCOUNT_REGISTERED", "PQC_SELF_TEST_COMPLETED", "FILE_UPLOADED", "HASH_GENERATED", "PERFORMANCE_SHA256", "FILE_ENCRYPTED", "PERFORMANCE_AES_256_GCM", "PQC_PROTECTION_CREATED", "PERFORMANCE_ML_KEM_768", "FILE_SIGNED", "PERFORMANCE_ML_DSA_65", "CONTROLLED_TAMPER", "TAMPERING_DETECTED", "BACKUP_RESTORED", "QUANTUM_THREAT", "SUSPICIOUS_ACTIVITY", "ATTACK_DETECTED", "SELF_HEALING_STARTED", "RSA_TEST_PATH_REVOKED", "KEY_REVOKED", "OLD_PROTECTION_REVOKED", "NEW_KEY_GENERATED", "NEW_PROTECTION_CREATED", "SIGNATURE_RECREATED", "FILE_MIGRATED", "INTEGRITY_VERIFIED", "SELF_HEALING_COMPLETED", "WEB_SESSIONS_REVOKED", "PERFORMANCE_MIGRATION", "REPEAT_ATTACK", "SECOND_ATTACK_REJECTED"]) {
        assert.ok(actions.includes(action), `Audit trail missing ${action}`);
    }

    const context = await jsonRequest(base, "/api/vault/security-context");
    assert.equal(context.response.ok, true);
    assert.equal(context.result.vaultState, "PQC_ACTIVE");
    assert.equal(context.result.files[0].signatureStatus, "VALID");
    assert.ok(context.result.recentEvents.some((event) => event.action === "SECOND_ATTACK_REJECTED"));
    const assistant = await jsonRequest(base, "/api/vault/assistant", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ question: "What protection is active now?" })
    });
    assert.equal(assistant.response.ok, true);
    assert.equal(assistant.result.provider, "LOCAL_SECURITY_CONTEXT");
    assert.match(assistant.result.answer, /PQC_ACTIVE/);
    assert.match(assistant.result.answer, /ML-KEM-768/);
    const recoveryAnswer = await jsonRequest(base, "/api/vault/assistant", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ question: "Was my file recovered?" })
    });
    assert.equal(recoveryAnswer.response.ok, true);
    assert.match(recoveryAnswer.result.answer, /SIGNATURE_AND_HASH_VALID/);

    const afterHealingBytes = Buffer.from("uploaded under the active post-migration key version", "utf8");
    const afterHealingForm = new FormData();
    afterHealingForm.append("file", new Blob([afterHealingBytes], { type: "text/plain" }), "after-healing.txt");
    const afterHealingUpload = await authorizedFetch(`${base}/api/vault/upload`, { method: "POST", body: afterHealingForm });
    assert.equal(afterHealingUpload.status, 201);
    const afterHealingRecord = await afterHealingUpload.json();
    assert.equal(afterHealingRecord.keyVersion, 2, "New uploads after healing must use the active key version");
    assert.ok(afterHealingRecord.performanceMs.uploadTotal >= 0);
    const afterHealingDetails = (await jsonRequest(base, `/api/vault/files/${afterHealingRecord.id}`)).result;
    assert.equal(afterHealingDetails.integrityStatus, "NOT_RECENTLY_VERIFIED");
    const afterHealingDownload = await authorizedFetch(`${base}/api/vault/files/${afterHealingRecord.id}/download`);
    assert.deepEqual(Buffer.from(await afterHealingDownload.arrayBuffer()), afterHealingBytes);

    const deleted = await jsonRequest(base, `/api/vault/files/${afterHealingRecord.id}`, { method: "DELETE" });
    assert.equal(deleted.response.ok, true, JSON.stringify(deleted.result));
    assert.equal(deleted.result.deleted, true);
    const afterDelete = await jsonRequest(base, "/api/vault/files");
    assert.equal(afterDelete.result.files.some((file) => file.id === afterHealingRecord.id), false);
    const deleteAudit = await jsonRequest(base, "/api/vault/audit");
    assert.ok(deleteAudit.result.events.some((event) => event.action === "FILE_DELETED"));

    const rewrapped = await jsonRequest(base, "/api/vault/change-passphrase", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ passphrase: rotatedPassphrase })
    });
    assert.equal(rewrapped.response.ok, true, JSON.stringify(rewrapped.result));
    assert.equal(rewrapped.result.updated, true);

    const loggedOut = await jsonRequest(base, "/api/vault/logout", { method: "POST" });
    assert.equal(loggedOut.result.loggedOut, true);
    const afterLogout = await jsonRequest(base, "/api/vault/files");
    assert.equal(afterLogout.response.status, 401, "Logout must revoke the browser session");

    await stopServer(serverProcess);
    serverProcess = null;
    ({ child: serverProcess } = await startServer(port));
    status = (await jsonRequest(base, "/api/vault/status")).result;
    assert.equal(status.unlocked, false, "Vault must lock after restart");
    assert.equal(status.authenticated, false, "Browser sessions must not survive restart");
    let wrongPass = await jsonRequest(base, "/api/vault/login", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ username: "acceptance-user", password: passphrase })
    });
    assert.equal(wrongPass.response.ok, false, "Incorrect passphrase must not unlock key bundle");
    opened = await jsonRequest(base, "/api/vault/login", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ username: "acceptance-user", password: rotatedPassphrase })
    });
    assert.equal(opened.response.ok, true, JSON.stringify(opened.result));
    assert.equal(opened.result.state, "PQC_ACTIVE");
    assert.equal(opened.result.keyVersion, 2);
    const keyStatus = await jsonRequest(base, "/api/vault/key-status");
    assert.equal(keyStatus.response.ok, true);
    assert.equal(keyStatus.result.privateKeysExported, false);
    assert.ok(Buffer.from(keyStatus.result.kemPublicKey, "base64").length > 0);
    details = (await jsonRequest(base, `/api/vault/files/${uploaded.id}`)).result;
    assert.equal(details.version, 2);
    recoveredResponse = await authorizedFetch(`${base}/api/vault/files/${uploaded.id}/download`);
    assert.deepEqual(new Uint8Array(await recoveredResponse.arrayBuffer()), original);

    const page = await fetch(`${base}/vault.html`);
    assert.equal(page.status, 200);
    assert.match(await page.text(), /data-vault-page="overview"/);
    for (const page of ["/vault.html", "/files.html", "/threat.html", "/keys.html", "/audit.html", "/assistant.html", "/workflow.html", "/rsa.html", "/quantum.html", "/pqc.html"]) {
        assert.equal((await fetch(`${base}${page}`)).status, 200, `${page} must remain available`);
    }

    console.log("PASS: account registration/login, session authorization/revocation, password-wrapped PQC key bundle");
    console.log("PASS: real ML-KEM encapsulation/decapsulation and ML-DSA sign/verify self-test");
    console.log("PASS: SHA-256, AES-256-GCM envelope/tag, canonical ML-DSA signature, exact verified recovery");
    console.log("PASS: ciphertext tampering, authenticated backup restoration, one-use attack session");
    console.log("PASS: fixed toy RSA evidence, key rotation, file migration/re-sign/verify, repeat-attack explanation");
    console.log("PASS: password rewrap, process restart, wrong-password rejection, file deletion, PQC version-2 recovery, audit events, preserved RSA/Shor pages");
} finally {
    await stopServer(serverProcess);
    await rm(root, { recursive: true, force: true });
}
