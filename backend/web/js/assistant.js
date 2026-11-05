const conversation = document.querySelector("#conversation");

function addMessage(who, content) {
    const article = document.createElement("article");
    article.className = who === "You" ? "user-message" : "assistant-message";
    const title = document.createElement("b");
    title.textContent = who;
    const paragraph = document.createElement("p");
    paragraph.textContent = content;
    article.append(title, paragraph);
    conversation.append(article);
    conversation.scrollTop = conversation.scrollHeight;
}

function displayContext(context) {
    const values = [
        ["Vault state", context.vaultState],
        ["Active protection", context.activeProtection],
        ["Key version", `v${context.activeKeyVersion}`],
        ["Self-healing", context.selfHealingStatus],
        ["Signatures", context.signatureStatus],
        ["Integrity", context.integrityStatus],
        ["Threat events", context.attackHistory.length]
    ];
    const summary = document.querySelector("#contextSummary");
    summary.replaceChildren(...values.map(([label, value]) => {
        const row = document.createElement("div");
        const term = document.createElement("dt"); term.textContent = label;
        const detail = document.createElement("dd"); detail.textContent = value;
        row.append(term, detail); return row;
    }));
    const files = document.querySelector("#contextFiles");
    files.replaceChildren();
    if (!context.files.length) {
        const item = document.createElement("li"); item.textContent = "No protected files are recorded."; files.append(item);
    } else context.files.forEach((file) => {
        const item = document.createElement("li");
        item.textContent = `${file.filename} · ${file.sizeBytes} bytes · v${file.version} · signature ${file.signatureStatus} · integrity ${file.integrityStatus}`;
        files.append(item);
    });
    const events = document.querySelector("#contextEvents");
    events.replaceChildren();
    context.recentEvents.slice(0, 6).forEach((event) => {
        const item = document.createElement("li");
        const head = document.createElement("div"); head.className = "audit-heading";
        const action = document.createElement("span"); action.className = "audit-action"; action.textContent = event.action;
        const time = document.createElement("time"); time.className = "audit-time"; time.dateTime = event.time; time.textContent = new Date(event.time).toLocaleString();
        const detail = document.createElement("small"); detail.className = "audit-detail"; detail.textContent = `v${event.version} · ${event.result}`;
        head.append(action, time); item.append(head, detail); events.append(item);
    });
}

async function refreshContext() {
    const context = await vaultApi("/api/vault/security-context");
    displayContext(context);
}

async function ask(question) {
    if (!question.trim()) return;
    addMessage("You", question);
    try {
        const result = await vaultApi("/api/vault/assistant", {
            method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8" },
            body: new URLSearchParams({ question })
        });
        addMessage("VaultAI · local context", result.answer);
        vaultNotice(document.querySelector("#assistantNotice"), "Answered from the current backend context.", "success");
    } catch (error) {
        addMessage("VaultAI", `I could not answer because the backend request failed: ${error.message}`);
        vaultNotice(document.querySelector("#assistantNotice"), error.message, "error");
    }
}

document.querySelector("#assistantForm").addEventListener("submit", async (event) => {
    event.preventDefault(); const input = document.querySelector("#assistantQuestion");
    const question = input.value; input.value = ""; await ask(question);
});
document.querySelectorAll(".suggested-questions button").forEach((button) => button.addEventListener("click", () => ask(button.textContent)));
document.querySelector("#clearChat").addEventListener("click", () => conversation.replaceChildren());
document.querySelector("#refreshContext").addEventListener("click", () => refreshContext().catch((error) => vaultNotice(document.querySelector("#assistantNotice"), error.message, "error")));
window.addEventListener("vault:ready", (event) => { if (event.detail.unlocked) refreshContext().catch((error) => vaultNotice(document.querySelector("#assistantNotice"), error.message, "error")); });
