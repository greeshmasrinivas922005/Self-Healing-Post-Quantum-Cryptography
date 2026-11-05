const conversation = document.querySelector("#conversation");
const history = [];
const providerBadge = document.querySelector("#assistantProvider");
let latestContext;

function addMessage(who, content) {
    const article = document.createElement("article");
    article.className = who === "You" ? "user-message" : "assistant-message";
    const title = document.createElement("b"); title.textContent = who;
    const paragraph = document.createElement("p"); paragraph.textContent = content;
    article.append(title, paragraph); conversation.append(article);
    conversation.scrollTop = conversation.scrollHeight;
}

function renderContext(context) {
    latestContext = context;
    const values = [["Vault state", context.vaultState], ["Protection", context.activeProtection],
        ["Active key", `v${context.activeKeyVersion}`], ["Self-healing", context.selfHealingStatus],
        ["Signatures", context.signatureStatus], ["Integrity", context.integrityStatus],
        ["Threat events", context.attackHistory.length]];
    const summary = document.querySelector("#contextSummary");
    summary.replaceChildren(...values.map(([label, value]) => {
        const row = document.createElement("div"), term = document.createElement("dt"), detail = document.createElement("dd");
        term.textContent = label; detail.textContent = value ?? "Unknown"; row.append(term, detail); return row;
    }));
    const files = document.querySelector("#contextFiles"); files.replaceChildren();
    if (!context.files.length) { const item = document.createElement("li"); item.textContent = "No protected files are recorded."; files.append(item); }
    else context.files.forEach((file) => {
        const item = document.createElement("li");
        item.textContent = `${file.filename} · ${file.sizeBytes} bytes · v${file.version} · signature ${file.signatureStatus} · integrity ${file.integrityStatus}`;
        files.append(item);
    });
    const events = document.querySelector("#contextEvents"); events.replaceChildren();
    context.recentEvents.slice(0, 6).forEach((event) => {
        const item = document.createElement("li"), head = document.createElement("div"); head.className = "audit-heading";
        const action = document.createElement("span"); action.className = "audit-action"; action.textContent = event.action;
        const time = document.createElement("time"); time.className = "audit-time"; time.dateTime = event.time;
        time.textContent = new Date(event.time).toLocaleString();
        const detail = document.createElement("small"); detail.className = "audit-detail";
        detail.textContent = `v${event.version} · ${event.result}`; head.append(action, time); item.append(head, detail); events.append(item);
    });
    const integrity = String(context.integrityStatus).toUpperCase();
    const signatures = String(context.signatureStatus).toUpperCase();
    const issue = integrity.includes("FAIL") || integrity.includes("TAMPER") || signatures.includes("FAIL");
    document.querySelector("#aiPosture").textContent = issue ? "Review required" : "No recorded integrity failure";
    document.querySelector("#aiPostureDetail").textContent = issue
        ? "Backend status reports a failed integrity or signature check. Open the file vault and investigate."
        : `${context.files.length} protected file(s); state: ${context.vaultState}. This is a status summary, not an intrusion detector.`;
    const hasFiles = context.files.length > 0;
    document.querySelector("#aiRecommendation").textContent = hasFiles ? "Verify a recovery path" : "Protect a test file";
    document.querySelector("#aiRecommendationDetail").textContent = hasFiles
        ? "Use the recovery view to validate a selected file when appropriate; confirm downloads contain the expected data."
        : "Upload a non-sensitive sample to exercise encryption, signature verification, and recovery end to end.";
}

async function refreshContext() {
    const context = await vaultApi("/api/vault/security-context");
    renderContext(context);
}

async function ask(question) {
    const normalized = question.trim();
    if (!normalized) return;
    addMessage("You", normalized);
    history.push({ role: "user", content: normalized });
    const form = document.querySelector("#assistantForm"), submit = form.querySelector("button[type='submit']");
    submit.disabled = true; submit.textContent = "Thinking…";
    try {
        const result = await vaultApi("/api/vault/assistant", {
            method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8" },
            body: new URLSearchParams({ question: normalized, history: JSON.stringify(history.slice(-8)) })
        });
        addMessage(`VaultAI · ${result.provider}`, result.answer);
        history.push({ role: "assistant", content: result.answer });
        providerBadge.textContent = result.provider;
        if (result.model) providerBadge.textContent += ` · ${result.model}`;
        const providerNotice = result.providerMessage
            || (result.provider === "OPENAI_RESPONSES"
                ? `Answered by ${result.model || "the configured AI model"}; VaultIQ-specific security facts use sanitized backend context.`
                : "Answered using the local project-focused knowledge base. Configure OPENAI_API_KEY on the server for broad open-ended answers.");
        vaultNotice(document.querySelector("#assistantNotice"), providerNotice, result.provider === "OPENAI_RESPONSES" ? "success" : "");
    } catch (error) {
        history.pop();
        addMessage("VaultAI", `The assistant request failed: ${error.message}`);
        vaultNotice(document.querySelector("#assistantNotice"), error.message, "error");
    } finally { submit.disabled = false; submit.innerHTML = 'Ask VaultAI <span aria-hidden="true">→</span>'; }
}

document.querySelector("#assistantForm").addEventListener("submit", async (event) => {
    event.preventDefault(); const input = document.querySelector("#assistantQuestion"), question = input.value;
    input.value = ""; await ask(question);
});
document.querySelectorAll(".suggested-questions button").forEach((button) => button.addEventListener("click", () => ask(button.textContent)));
document.querySelector("#clearChat").addEventListener("click", () => {
    history.length = 0;
    conversation.replaceChildren();
    addMessage("VaultAI", "Conversation cleared. Ask me about project security, cryptography, or the current recorded vault state.");
});
document.querySelector("#refreshContext").addEventListener("click", () => refreshContext().catch((error) => vaultNotice(document.querySelector("#assistantNotice"), error.message, "error")));
window.addEventListener("vault:ready", (event) => {
    if (event.detail.unlocked) refreshContext().catch((error) => vaultNotice(document.querySelector("#assistantNotice"), error.message, "error"));
});
