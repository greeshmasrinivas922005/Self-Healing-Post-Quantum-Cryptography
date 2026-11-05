function addSummaryRows(target, items) {
    target.replaceChildren();
    items.forEach(([label, value]) => {
        const row = document.createElement("div"), term = document.createElement("dt"), detail = document.createElement("dd");
        term.textContent = label; detail.textContent = value; row.append(term, detail); target.append(row);
    });
}

async function loadOverview() {
    const [status, context, audit] = await Promise.all([
        vaultApi("/api/vault/status"), vaultApi("/api/vault/security-context"), vaultApi("/api/vault/audit")
    ]);
    const events = audit.events;
    const files = context.files;
    const latestFile = files[0] || null;
    const uploadEvidence = latestFile && events.find((event) => event.action === "FILE_UPLOADED" && event.record === latestFile.id);
    const fileRecovery = latestFile && events.find((event) => event.action === "FILE_RECOVERED"
        && event.record === latestFile.id && event.version === latestFile.version);
    const latestSecurityEvent = events.find((event) => /NETWORK|ATTACK|THREAT|RSA_VULNERABILITY|SELF_HEALING/i.test(event.action));
    const threatDetected = events.some((event) => event.action === "RSA_VULNERABILITY_DETECTED");
    const healed = context.selfHealingStatus === "COMPLETED";

    document.querySelector("#vaultState").textContent = status.state.replaceAll("_", " ");
    document.querySelector("#keyVersion").textContent = `v${status.keyVersion}`;
    document.querySelector("#fileCount").textContent = String(status.fileCount);
    document.querySelector("#threatStatus").textContent = threatDetected ? "CONTROLLED TEST DETECTED" : "NO TEST EVENT RECORDED";
    document.querySelector("#providerStatus").textContent = `JDK ${status.javaVersion} · ${status.kem}`;
    document.querySelector("#recoveredCount").textContent = String(events.filter((event) => event.action === "FILE_RECOVERED").length);
    document.querySelector("#attackCount").textContent = String(events.filter((event) => event.action === "CONTROLLED_ATTACK_SESSION_ISSUED").length);
    document.querySelector("#healingSummary").textContent = healed ? "Completed · verified migration recorded" : "Not completed · awaiting controlled evidence";
    document.querySelector("#filesSummary").textContent = `${status.fileCount} protected file${status.fileCount === 1 ? "" : "s"}`;
    document.querySelector("#integritySummary").textContent = context.integrityStatus.replaceAll("_", " ");
    document.querySelector("#lastEventSummary").textContent = latestSecurityEvent ? `${latestSecurityEvent.action.replaceAll("_", " ")} · ${new Date(latestSecurityEvent.time).toLocaleString()}` : "No security test event recorded";

    const summary = document.querySelector("#finalSecuritySummary");
    addSummaryRows(summary, [
        ["File", latestFile ? latestFile.filename : "No protected file"],
        ["Protection at ingest", latestFile ? `${uploadEvidence ? `PQC v${uploadEvidence.version}` : `PQC v${latestFile.version}`}${uploadEvidence && uploadEvidence.version !== latestFile.version ? ` → v${latestFile.version} after migration` : ""} · RSA was not used for file encryption` : "Not applicable"],
        ["Threat", threatDetected ? "Fixed educational RSA target factored · controlled event recorded" : "No threat event recorded"],
        ["Self-healing", context.selfHealingStatus],
        ["Old PQC key material", healed ? `v${status.keyVersion - 1} retired after verified migration` : "No retired version recorded"],
        ["Current protection", `${context.activeProtection} · v${context.activeKeyVersion}`],
        ["Metadata signature", context.signatureStatus],
        ["File integrity", latestFile ? latestFile.integrityStatus : context.integrityStatus],
        ["Recovery", latestFile ? (fileRecovery ? `Verified recovery recorded · ${fileRecovery.time}` : "No successful recovery recorded for this file") : context.recoveryStatus],
        ["Second attack", events.some((event) => event.action === "SECOND_ATTACK_REJECTED") ? "Old test session / retired key path rejected" : "No second-attack rejection recorded"],
        ["Audit", `${events.length} persisted event(s)`],
        ["VaultAI", "Available · local security-context assistant"]
    ]);

    const recentList = document.querySelector("#recentEvents"); recentList.replaceChildren();
    if (!events.length) {
        const empty = document.createElement("li"); empty.className = "empty-row"; empty.textContent = "No operations recorded yet."; recentList.append(empty); return;
    }
    events.slice(0, 5).forEach((event) => {
        const item = document.createElement("li"), heading = document.createElement("div"); heading.className = "audit-heading";
        const action = document.createElement("span"); action.className = "audit-action"; action.textContent = event.action.replaceAll("_", " ");
        const time = document.createElement("time"); time.className = "audit-time"; time.dateTime = event.time;
        time.textContent = new Date(event.time).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }); heading.append(action, time);
        const detail = document.createElement("span"); detail.className = "audit-detail";
        detail.textContent = `v${event.version} · ${event.result}${event.record ? ` · ${event.record.slice(0, 8)}` : ""}`;
        item.append(heading, detail); recentList.append(item);
    });
}

window.addEventListener("vault:ready", (event) => {
    if (event.detail.unlocked) loadOverview().catch((error) => vaultNotice(document.querySelector("#unlockNotice"), error.message, "error"));
});
