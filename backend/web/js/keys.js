function addKeyRows(target, rows) {
    const list = document.querySelector(target);
    list.replaceChildren();
    rows.forEach(([label, value]) => {
        const row = document.createElement("div");
        const key = document.createElement("dt");
        const detail = document.createElement("dd");
        key.textContent = label;
        detail.textContent = value ?? "—";
        row.append(key, detail);
        list.append(row);
    });
}

async function loadKeyStore() {
    const key = await vaultApi("/api/vault/key-status");
    document.querySelector("#activeKeyTitle").textContent = `Key version ${key.keyVersion}`;
    addKeyRows("#keySummary", [["Vault state", key.state.replaceAll("_", " ")], ["KEM", key.kem], ["KEM provider", key.kemProvider], ["KEM public-key format", `${key.kemPublicKeyFormat} · ${key.kemPublicKeyBytes} bytes`], ["Signature", key.signature], ["Signature provider", key.signatureProvider], ["Signature public-key format", `${key.signaturePublicKeyFormat} · ${key.signaturePublicKeyBytes} bytes`], ["Private keys", "Encrypted at rest · never exported"], ["Bundle encryption", key.bundleEncryption]]);
    const publicKeys = document.querySelector("#publicKeys");
    publicKeys.replaceChildren();
    [["ML-KEM public key", key.kemPublicKey], ["ML-DSA public key", key.signaturePublicKey]].forEach(([label, value]) => {
        const row = document.createElement("div");
        const name = document.createElement("span");
        const code = document.createElement("code");
        name.textContent = label;
        code.textContent = value;
        row.append(name, code);
        publicKeys.append(row);
    });
    const events = await vaultApi("/api/vault/audit");
    const keyEvents = events.events.filter((event) => /KEY|PASSPHRASE|SELF_HEALING/.test(event.action));
    const list = document.querySelector("#keyEvents");
    list.replaceChildren();
    if (!keyEvents.length) {
        const empty = document.createElement("li");
        empty.className = "empty-row";
        empty.textContent = "No key lifecycle events yet.";
        list.append(empty);
    } else {
        keyEvents.slice(0, 12).forEach((event) => {
            const item = document.createElement("li");
            item.textContent = `${event.action.replaceAll("_", " ")} · v${event.version} · ${event.result}`;
            list.append(item);
        });
    }
}

document.querySelector("#changePassphraseForm").addEventListener("submit", async (event) => {
    event.preventDefault();
    const input = document.querySelector("#newPassphrase");
    const button = document.querySelector("#changePassphraseButton");
    button.disabled = true;
    try {
        const result = await vaultApi("/api/vault/change-passphrase", {
            method: "POST",
            headers: { "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8" },
            body: new URLSearchParams({ passphrase: input.value })
        });
        input.value = "";
        vaultNotice(document.querySelector("#passphraseNotice"), result.message, "success");
        await loadKeyStore();
    } catch (error) {
        input.value = "";
        vaultNotice(document.querySelector("#passphraseNotice"), error.message, "error");
    } finally {
        button.disabled = false;
    }
});

window.addEventListener("vault:ready", (event) => {
    if (event.detail.unlocked) loadKeyStore().catch((error) => vaultNotice(document.querySelector("#passphraseNotice"), error.message, "error"));
});
