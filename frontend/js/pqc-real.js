function setText(selector, value) {
    document.querySelector(selector).textContent = value ?? "Unavailable";
}

function addResult(label, value, parent) {
    const block = document.createElement("div");
    block.className = "evidence-block";
    const heading = document.createElement("h3");
    heading.textContent = label;
    const content = document.createElement("code");
    content.textContent = value ?? "Unavailable";
    block.append(heading, content);
    parent.append(block);
}

async function loadPqcKeyStatus() {
    const keys = await vaultApi("/api/vault/key-status");
    setText("#pqcVersion", `v${keys.keyVersion}`);
    setText("#kemProvider", keys.kemProvider);
    setText("#dsaProvider", keys.signatureProvider);
    const kemBytes = Uint8Array.from(atob(keys.kemPublicKey), (character) => character.charCodeAt(0));
    const dsaBytes = Uint8Array.from(atob(keys.signaturePublicKey), (character) => character.charCodeAt(0));
    const kemFingerprint = vaultHex(new Uint8Array(await crypto.subtle.digest("SHA-256", kemBytes)));
    const dsaFingerprint = vaultHex(new Uint8Array(await crypto.subtle.digest("SHA-256", dsaBytes)));
    setText("#kemFingerprint", kemFingerprint);
    setText("#dsaFingerprint", dsaFingerprint);
}

async function runPqcOperations() {
    const button = document.querySelector("#runPqcTest");
    const notice = document.querySelector("#pqcNotice");
    const results = document.querySelector("#pqcResults");
    button.disabled = true;
    vaultNotice(notice, "Running ML-KEM encapsulation/decapsulation and ML-DSA sign/verify in the Java backend…");
    try {
        const result = await vaultApi("/api/vault/pqc-self-test", { method: "POST" });
        results.replaceChildren();
        addResult("ML-KEM encapsulation bytes", `${result.encapsulationBytes} · ${result.encapsulation}`, results);
        addResult("Shared-secret SHA-256 fingerprint", result.sharedSecretFingerprint, results);
        addResult("Decapsulation comparison", result.decapsulationMatches ? "MATCH" : "MISMATCH", results);
        addResult("Signed test metadata SHA-256", result.metadataDigest, results);
        addResult("ML-DSA signature", `${result.signatureBytes} bytes · ${result.signature}`, results);
        addResult("Signature verification", result.signatureValid ? "VALID" : "INVALID", results);
        results.hidden = false;
        vaultNotice(notice, `Real ${result.kem} and ${result.signatureAlgorithm} operations completed using ${result.kemProvider} / ${result.signatureProvider}.`, "success");
    } catch (error) {
        vaultNotice(notice, error.message, "error");
        results.hidden = true;
    } finally {
        button.disabled = false;
    }
}

document.querySelector("#runPqcTest").addEventListener("click", runPqcOperations);
window.addEventListener("vault:ready", (event) => {
    if (event.detail.unlocked) loadPqcKeyStatus().catch((error) => vaultNotice(document.querySelector("#pqcNotice"), error.message, "error"));
});
