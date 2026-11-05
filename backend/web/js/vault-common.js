window.vaultApi = async function (path, options = {}) {
    const response = await fetch(path, options);
    const contentType = response.headers.get("content-type") || "";
    const result = contentType.includes("application/json") ? await response.json() : null;
    if (!response.ok) throw new Error(result?.error || `Request failed (${response.status}).`);
    return result;
};

window.vaultNotice = function (element, message, kind = "") {
    element.textContent = message;
    element.classList.toggle("error", kind === "error");
    element.classList.toggle("success", kind === "success");
};

window.vaultBytesLabel = function (bytes) {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KiB`;
    return `${(bytes / (1024 * 1024)).toFixed(2)} MiB`;
};

window.vaultHex = function (bytes) {
    return Array.from(bytes, (value) => value.toString(16).padStart(2, "0")).join("");
};

window.vaultState = null;

const vaultNavigation = [
    ["Dashboard", "vault.html", "overview"],
    ["File Vault", "files.html", "files"],
    ["Upload", "workflow.html?view=upload", "upload"],
    ["Crypto Process", "workflow.html?view=process", "process"],
    ["PQC Protection", "workflow.html?view=pqc", "pqc"],
    ["Security Monitor", "workflow.html?view=monitor", "monitor"],
    ["Attack Lab", "workflow.html?view=attack", "attack"],
    ["Self-Healing", "workflow.html?view=healing", "healing"],
    ["Recovery", "workflow.html?view=recovery", "recovery"],
    ["Audit Trail", "audit.html", "audit"],
    ["VaultAI", "assistant.html", "assistant"],
    ["Settings", "keys.html", "keys"]
];

document.querySelectorAll(".vault-nav").forEach((nav) => {
    nav.replaceChildren(...vaultNavigation.map(([label, href, key]) => {
        const link = document.createElement("a");
        link.href = href;
        link.textContent = label;
        link.dataset.nav = key;
        return link;
    }));
});

async function loadVaultShell() {
    const online = document.querySelector("#serverState");
    try {
        const status = await window.vaultApi("/api/vault/status");
        online.classList.add("online");
        online.classList.remove("offline");
        online.lastChild.textContent = status.remoteLabEnabled ? "HTTPS LAB" : "LOCAL SERVER";
        window.vaultState = status;
        document.querySelectorAll("[data-nav]").forEach((link) => {
            const view = new URLSearchParams(location.search).get("view");
            const page = view || document.body.dataset.vaultPage;
            link.classList.toggle("current", link.dataset.nav === page);
        });
        const locked = document.querySelector("#unlockPanel");
        const workspace = document.querySelector("#vaultWorkspace");
        locked.hidden = status.unlocked;
        workspace.hidden = !status.unlocked;
        if (!status.unlocked) {
            document.querySelector("#unlockTitle").textContent = status.keyVersion ? "Unlock the existing vault" : "Create your vault";
            document.querySelector("#unlockDescription").textContent = status.keyVersion
                ? "Enter the passphrase used to encrypt the stored PQC private-key bundle."
                : "Choose a passphrase to initialize and encrypt the local PQC private-key bundle.";
            document.querySelector("#vaultPassphrase").autocomplete = status.keyVersion ? "current-password" : "new-password";
        }
        window.dispatchEvent(new CustomEvent("vault:ready", { detail: status }));
    } catch (error) {
        online.classList.add("offline");
        online.classList.remove("online");
        online.lastChild.textContent = "OFFLINE";
        const message = document.querySelector("#unlockNotice");
        window.vaultNotice(message, error.message, "error");
    }
}

document.querySelector("#unlockForm").addEventListener("submit", async (event) => {
    event.preventDefault();
    const input = document.querySelector("#vaultPassphrase");
    const button = document.querySelector("#unlockButton");
    button.disabled = true;
    button.textContent = "Unlocking…";
    window.vaultNotice(document.querySelector("#unlockNotice"), "Checking the encrypted PQC key bundle…");
    try {
        await window.vaultApi("/api/vault/unlock", {
            method: "POST",
            headers: { "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8" },
            body: new URLSearchParams({ passphrase: input.value })
        });
        input.value = "";
        await loadVaultShell();
    } catch (error) {
        input.value = "";
        window.vaultNotice(document.querySelector("#unlockNotice"), error.message, "error");
    } finally {
        button.disabled = false;
        button.textContent = "Unlock";
    }
});

loadVaultShell();
