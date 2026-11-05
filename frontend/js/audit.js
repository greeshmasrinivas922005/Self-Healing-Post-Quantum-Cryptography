let allAuditEvents = [];

function eventFields(event) {
    const result = String(event.result || "");
    const source = event.source || result.match(/(?:^|\s)SOURCE=([^\s]+)/)?.[1] || (event.action.startsWith("NETWORK_") || event.action.includes("ATTACK") ? "Not recorded" : "Vault service");
    const destination = event.destination || result.match(/(?:^|\s)DESTINATION=([^\s]+)/)?.[1] || "";
    const targetName = event.target || result.match(/(?:^|\s)TARGET=([^\s]+)/)?.[1] || (event.record ? `FILE:${event.record}` : "VAULT");
    const endpoint = event.endpoint || result.match(/(?:^|\s)ENDPOINT=([^\s]+)/)?.[1] || "";
    const target = [destination && `destination ${destination}`, targetName, endpoint].filter(Boolean).join(" · ");
    const status = event.status || (/REJECTED|FAILED|INVALID/i.test(event.action) || /REJECTED|FAILED|MISMATCH/i.test(result) ? "REJECTED"
        : /DETECTED|COMPROMISED/i.test(event.action) ? "DETECTED"
            : /VERIFIED|COMPLETED|RESTORED/i.test(event.action) ? "VERIFIED"
                : "RECORDED");
    const details = result.replace(/(?:^|\s)(?:SOURCE|DESTINATION|TARGET|ENDPOINT)=[^\s]+/g, "").trim() || "No additional detail.";
    return { source, target, status, details };
}

function renderAudit() {
    const query = document.querySelector("#auditFilter").value.trim().toLowerCase();
    const rows = document.querySelector("#auditRows"); rows.replaceChildren();
    const events = allAuditEvents.filter((event) => {
        const fields = eventFields(event);
        return `${event.time} ${event.action} ${event.record} ${event.version} ${fields.source} ${fields.target} ${fields.status} ${fields.details}`.toLowerCase().includes(query);
    });
    if (!events.length) {
        const row = document.createElement("tr"), empty = document.createElement("td");
        empty.colSpan = 6; empty.className = "empty-row"; empty.textContent = "No matching events."; row.append(empty); rows.append(row); return;
    }
    events.forEach((event) => {
        const row = document.createElement("tr"), fields = eventFields(event);
        const time = document.createElement("td"); time.className = "audit-time-cell"; time.textContent = `${new Date(event.time).toISOString().replace("T", " ").replace("Z", "")} UTC`;
        const action = document.createElement("td"); action.textContent = event.action.replaceAll("_", " ");
        const source = document.createElement("td"); source.textContent = fields.source;
        const target = document.createElement("td"); target.textContent = fields.target;
        const status = document.createElement("td"); status.textContent = fields.status; status.className = `audit-state ${fields.status.toLowerCase()}`;
        const details = document.createElement("td"); details.textContent = `${fields.details} · record=${event.record || "—"} · key=v${event.version}`;
        row.append(time, action, source, target, status, details); rows.append(row);
    });
}

async function loadAudit() {
    const response = await vaultApi("/api/vault/audit");
    allAuditEvents = response.events;
    document.querySelector("#auditTotal").textContent = String(allAuditEvents.length);
    renderAudit();
}

document.querySelector("#auditFilter").addEventListener("input", renderAudit);
document.querySelector("#refreshAudit").addEventListener("click", () => loadAudit().catch((error) => vaultNotice(document.querySelector("#auditNotice"), error.message, "error")));
window.addEventListener("vault:ready", (event) => {
    if (event.detail.unlocked) loadAudit().catch((error) => vaultNotice(document.querySelector("#auditNotice"), error.message, "error"));
});
