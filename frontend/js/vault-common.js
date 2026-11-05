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

const productStylesheet = document.createElement("link");
productStylesheet.rel = "stylesheet";
productStylesheet.href = "css/product.css";
document.head.append(productStylesheet);

const usernameLabel = document.createElement("label");
usernameLabel.htmlFor = "vaultUsername";
usernameLabel.textContent = "Username";
const usernameInput = document.createElement("input");
usernameInput.id = "vaultUsername";
usernameInput.name = "username";
usernameInput.autocomplete = "username";
usernameInput.required = true;
usernameInput.minLength = 3;
usernameInput.maxLength = 40;
usernameInput.pattern = "[A-Za-z0-9][A-Za-z0-9._-]{2,39}";
const accountPasswordLabel = document.querySelector("label[for='vaultPassphrase']");
accountPasswordLabel.textContent = "Account password";
accountPasswordLabel.before(usernameLabel, usernameInput);

const vaultNavigation = [
    ["Dashboard", "vault.html", "overview"],
    ["File Vault", "files.html", "files"],
    ["Upload", "workflow.html?view=upload", "upload"],
    ["Crypto Process", "workflow.html?view=process", "process"],
    ["PQC Protection", "workflow.html?view=pqc", "pqc"],
    ["Security Monitor", "workflow.html?view=monitor", "monitor"],
    ["Attack Lab", "workflow.html?view=attack", "attack"],
    ["Remote Attack Demo", "workflow.html?view=remote", "remote"],
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

document.querySelectorAll('.top-actions a.top-link').forEach((link) => {
    if (link.textContent.trim().toLowerCase() === "message lab") link.href = "index.html";
});

async function loadVaultShell() {
    const online = document.querySelector("#serverState");
    try {
        const status = await window.vaultApi("/api/vault/status");
        status.unlocked = status.unlocked && status.authenticated;
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
            const existingBundle = !status.accountConfigured && status.keyBundleConfigured;
            document.querySelector("#unlockTitle").textContent = status.accountConfigured ? "Sign in to VaultIQ"
                : existingBundle ? "Unlock your existing vault" : "Create your VaultIQ account";
            document.querySelector("#unlockDescription").textContent = status.accountConfigured
                ? "Your account password also unlocks the locally encrypted PQC key bundle."
                : existingBundle
                    ? "An encrypted vault already exists without an account. Enter its previous vault passphrase to unlock it and add account protection; your files and keys will be preserved."
                    : "Create an account to initialize the encrypted PQC key bundle.";
            accountPasswordLabel.textContent = existingBundle ? "Existing vault passphrase" : "Account password";
            document.querySelector("#vaultPassphrase").autocomplete = status.accountConfigured || existingBundle ? "current-password" : "new-password";
            document.querySelector("#vaultPassphrase").minLength = existingBundle ? 10 : 12;
            document.querySelector("#unlockButton").textContent = status.accountConfigured ? "Sign in"
                : existingBundle ? "Unlock & create account" : "Create account";
            usernameInput.hidden = false;
            usernameLabel.hidden = false;
            usernameInput.value = "";
        }
        let sessionButton = document.querySelector("#vaultSessionButton");
        if (!sessionButton) {
            sessionButton = document.createElement("button");
            sessionButton.id = "vaultSessionButton";
            sessionButton.type = "button";
            sessionButton.className = "top-link";
            document.querySelector(".top-actions").prepend(sessionButton);
            sessionButton.addEventListener("click", async () => {
                await window.vaultApi("/api/vault/logout", { method: "POST" });
                location.reload();
            });
        }
        sessionButton.hidden = !status.unlocked;
        sessionButton.textContent = "Sign out";
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
    button.textContent = "Please wait…";
    window.vaultNotice(document.querySelector("#unlockNotice"), "Verifying credentials and encrypted vault keys…");
    try {
        const register = !window.vaultState?.accountConfigured;
        await window.vaultApi(register ? "/api/vault/register" : "/api/vault/login", {
            method: "POST",
            headers: { "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8" },
            body: new URLSearchParams({ username: usernameInput.value, password: input.value })
        });
        input.value = "";
        await loadVaultShell();
    } catch (error) {
        input.value = "";
        window.vaultNotice(document.querySelector("#unlockNotice"), error.message, "error");
    } finally {
        button.disabled = false;
        const existingBundle = !window.vaultState?.accountConfigured && window.vaultState?.keyBundleConfigured;
        button.textContent = window.vaultState?.accountConfigured ? "Sign in"
            : existingBundle ? "Unlock & create account" : "Create account";
    }
});

loadVaultShell();
