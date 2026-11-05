const healingStages = [
    ["Initial PQC version active", ["VAULT_INITIALIZED"]],
    ["Toy threat evidence accepted", ["QUANTUM_THREAT"]],
    ["Initial RSA-test session invalidated", ["RSA_TEST_PATH_REVOKED", "ATTACK_SESSIONS_INVALIDATED"]],
    ["New ML-KEM / ML-DSA version generated", ["NEW_KEY_GENERATED"]],
    ["Files re-protected and re-signed", ["FILE_MIGRATED"]],
    ["Old PQC key version retired", ["KEY_REVOKED"]],
    ["Migrated files verified · PQC active", ["SELF_HEALING_COMPLETED"]]
];
let currentAttackPurpose = "initial";

function renderTimeline(state, events) {
    const seen = new Set(events.map((event) => event.action));
    const list = document.querySelector("#healingFlow");
    list.replaceChildren();
    healingStages.forEach(([label, evidence]) => {
        const complete = evidence.some((action) => seen.has(action));
        const item = document.createElement("li");
        item.className = `timeline-item${complete ? " complete" : ""}`;
        const marker = document.createElement("span");
        marker.className = "timeline-marker";
        marker.textContent = complete ? "✓" : "·";
        const text = document.createElement("span");
        text.textContent = label;
        item.append(marker, text);
        list.append(item);
    });
    document.querySelector("#threatState").textContent = state.replaceAll("_", " ");
}

async function loadThreatState() {
    const [status, audit] = await Promise.all([
        vaultApi("/api/vault/status"),
        vaultApi("/api/vault/audit")
    ]);
    renderTimeline(status.state, audit.events);
    const healed = status.state === "PQC_ACTIVE";
    currentAttackPurpose = healed ? "repeat" : "initial";
    document.querySelector("#repeatAttack").hidden = !healed;
    const launchButton = document.querySelector("#launchAttackLab");
    launchButton.disabled = healed;
    launchButton.textContent = healed ? "Initial walkthrough complete" : "Open preserved RSA / Shor teaching demo";
    document.querySelector("#rsaSessionState").textContent = healed ? "INITIAL SESSION INVALID" : "Not yet invalidated";
    document.querySelector("#oldPqcKeyState").textContent = healed ? `Version ${status.keyVersion - 1} retired after migration` : "Current PQC key remains active";
    document.querySelector("#activePqcState").textContent = `ML-KEM-768 · v${status.keyVersion}`;
    const params = new URLSearchParams(location.search);
    if (params.has("healed")) {
        vaultNotice(document.querySelector("#threatNotice"), "The backend validated the fixed test evidence, rotated keys, migrated and re-signed files, verified them, then retired the old PQC key version.", "success");
    } else if (params.has("repeat")) {
        vaultNotice(document.querySelector("#threatNotice"), "Repeat logged. Only the toy modulus was factored; the initial test session is invalid and vault files use the active PQC key version.", "success");
    }
    if (params.has("healed") || params.has("repeat")) {
        sessionStorage.removeItem("vaultAttackMode");
        sessionStorage.removeItem("vaultAttackSession");
    }
}

async function launchAttack(purpose) {
    try {
        const session = await vaultApi("/api/vault/attack-session", {
            method: "POST",
            headers: { "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8" },
            body: new URLSearchParams({ purpose })
        });
        sessionStorage.setItem("vaultAttackMode", purpose);
        sessionStorage.setItem("vaultAttackSession", session.sessionId);
        sessionStorage.setItem("userMessage", "AUTHORIZED TOY RSA TEST TARGET 3233");
        location.href = purpose === "repeat" ? "quantum.html" : "rsa.html";
    } catch (error) {
        vaultNotice(document.querySelector("#threatNotice"), error.message, "error");
    }
}

document.querySelector("#launchAttackLab").addEventListener("click", () => launchAttack(currentAttackPurpose));
document.querySelector("#repeatAttack").addEventListener("click", () => launchAttack("repeat"));
window.addEventListener("vault:ready", (event) => {
    if (event.detail.unlocked) loadThreatState().catch((error) => vaultNotice(document.querySelector("#threatNotice"), error.message, "error"));
});
