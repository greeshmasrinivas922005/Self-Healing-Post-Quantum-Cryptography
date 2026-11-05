const views = {
    upload: ["REAL FILE INGESTION", "Secure file upload", "Select a real file. The browser previews SHA-256 and the Java backend encrypts and stores it.", "upload"],
    process: ["CRYPTOGRAPHIC PIPELINE", "Cryptographic process", "Inspect the operations and current file records produced by the backend.", "process"],
    pqc: ["STANDARDIZED JDK OPERATIONS", "PQC protection", "The file vault uses this JDK's ML-KEM and ML-DSA implementations.", "pqc"],
    monitor: ["PERSISTED BACKEND EVIDENCE", "Security monitor", "Current vault state and individual recorded security events.", "monitor"],
    attack: ["CONTROLLED SECURITY DEMONSTRATION", "Attack lab", "Choose the local toy RSA walkthrough or the separately configured two-computer network lab.", "attack"],
    remote: ["AUTHORIZED TWO-COMPUTER DEMONSTRATION", "Remote lab", "Set up the private Computer A and Computer B lab, then review the backend evidence and key migration.", "remote"],
    healing: ["BACKEND-EXECUTED KEY LIFECYCLE", "Self-healing", "Review which migration steps the backend has recorded and which are still pending.", "healing"],
    recovery: ["VERIFIED FILE RESTORATION", "Recovery", "Download recovers a file only after signature, GCM tag, length, and SHA-256 checks succeed.", "recovery"]
};
const body = document.querySelector("#viewBody");
function node(tag, text, className) { const element = document.createElement(tag); if (text !== undefined) element.textContent = text; if (className) element.className = className; return element; }
function line(label, value) { const row = node("div", undefined, "workflow-row"); row.append(node("b", label), node("span", value)); body.append(row); }
function addLine(label, value) { const row = node("div", undefined, "workflow-row"); row.append(node("b", label), node("span", value)); document.querySelector("#workflowUploadForm")?.append(row); }
function section(title, eyebrow) { const panel = node("section", undefined, "workflow-section"); if (eyebrow) panel.append(node("p", eyebrow, "eyebrow")); panel.append(node("h2", title)); body.append(panel); return panel; }
function addEventTable(events, attackOnly = false) {
    const panel = section(attackOnly ? "Network and attack evidence" : "Recorded security events", "LATEST FIRST · PERSISTED AUDIT DATA");
    const wrap = node("div", undefined, "table-wrap"); const table = document.createElement("table");
    const heads = attackOnly ? ["TIME", "EVENT", "SOURCE IP", "DESTINATION · TEST TARGET", "ENDPOINT", "RESULT"] : ["TIME", "EVENT", "RECORD", "VERSION", "RESULT / EVIDENCE"];
    const thead = document.createElement("thead"), headRow = document.createElement("tr"); heads.forEach((label) => headRow.append(node("th", label))); thead.append(headRow); table.append(thead);
    const tb = document.createElement("tbody");
    const filtered = (attackOnly ? events.filter((event) => /NETWORK|ATTACK|THREAT|RSA/i.test(event.action)) : events).slice(0, 100);
    if (!filtered.length) { const tr = document.createElement("tr"), td = node("td", "No matching events are recorded.", "empty-row"); td.colSpan = heads.length; tr.append(td); tb.append(tr); }
    filtered.forEach((event) => {
        const tr = document.createElement("tr"), time = `${new Date(event.time).toISOString().replace("T", " ").replace("Z", "")} UTC`;
        if (attackOnly) {
            const evidence = String(event.result);
            const source = event.source || evidence.match(/(?:^|\s)SOURCE=([^\s]+)/)?.[1] || "—";
            const destination = event.destination || evidence.match(/(?:^|\s)DESTINATION=([^\s]+)/)?.[1] || "—";
            const target = event.target || evidence.match(/(?:^|\s)TARGET=([^\s]+)/)?.[1] || "—";
            const endpoint = event.endpoint || evidence.match(/(?:^|\s)ENDPOINT=([^\s]+)/)?.[1] || "—";
            [time, event.action, source, `${destination} · ${target}`, endpoint, evidence].forEach((value) => tr.append(node("td", String(value))));
        }
        else [time, event.action, event.record || "—", `v${event.version}`, event.result].forEach((value) => tr.append(node("td", String(value))));
        tb.append(tr);
    });
    table.append(tb); wrap.append(table); panel.append(wrap); return panel;
}
function addCopyCommand(label, command) {
    const row = node("div", undefined, "remote-command-row");
    const heading = node("div", undefined, "remote-command-heading");
    heading.append(node("b", label));
    const copy = node("button", "Copy command", "button button-outline");
    copy.type = "button";
    copy.addEventListener("click", async () => {
        try { await navigator.clipboard.writeText(command); copy.textContent = "Copied"; }
        catch { copy.textContent = "Select and copy below"; }
        setTimeout(() => { copy.textContent = "Copy command"; }, 1800);
    });
    heading.append(copy);
    const code = node("code", command);
    row.append(heading, code);
    body.append(row);
}
function addRemoteDemo(status, events) {
    const setup = section("Run the demonstration", "COMPUTER A HOSTS · COMPUTER B INITIATES");
    const mode = node("div", status.remoteLabEnabled ? "REMOTE HTTPS LAB ENABLED · mTLS + IP ALLOWLIST" : "REMOTE MODE DISABLED · run.bat is loopback only", `remote-mode-banner ${status.remoteLabEnabled ? "enabled" : "disabled"}`);
    const connected = events.some((event) => event.action === "NETWORK_CONNECTION");
    const healed = events.some((event) => event.action === "SELF_HEALING_COMPLETED");
    const flow = node("div", undefined, "two-computer-flow");
    const flowStages = [
        ["COMPUTER A", "Host the vault", status.remoteLabEnabled ? "HTTPS lab is running" : "Enable the private HTTPS lab", status.remoteLabEnabled ? "ready" : "setup", "A serves the protected vault and waits for Computer B."],
        ["COMPUTER B", "Send the test", connected ? "Authorized client connected" : "Waiting for Computer B", connected ? "complete" : "waiting", "B sends the fixed toy RSA test over TLS 1.3 with its client certificate."],
        ["COMPUTER A", "Heal and verify", healed ? `PQC active · key v${status.keyVersion}` : "Waiting for accepted test", healed ? "complete" : "waiting", "A validates the evidence, rotates PQC keys, migrates files, and records the result."]
    ];
    flowStages.forEach(([computer, title, state, stateClass, description], index) => {
        const card = node("article", undefined, `two-computer-step ${stateClass}`);
        card.append(node("span", computer, "two-computer-label"), node("h3", title), node("p", description), node("strong", state, "two-computer-state"));
        flow.append(card);
        if (index < flowStages.length - 1) flow.append(node("span", "→", "two-computer-arrow"));
    });
    const simpleGuide = node("p", "Simple view: Computer A hosts the vault → Computer B runs one authorized test → Computer A performs and records self-healing.", "two-computer-summary");
    setup.append(mode, flow, simpleGuide);
    const instructions = node("ol", undefined, "remote-steps");
    [
        "On Computer A, create the short-lived lab certificates for A’s private IP. Set the exact Computer B IP as the allowed client address, then start the server with tools\\run-authorized-lab.ps1 -Role server. Keep the lab token and certificate files private.",
        "On Computer A, open the printed HTTPS URL using A’s private IP (not localhost), trust the lab certificate for this isolated demo, sign in, and upload a harmless sample file. The session must be unlocked before Computer B’s request; the file lets you show real migration and verification.",
        "Copy backend\\AttackLabClient.java, tools\\run-authorized-lab.ps1, and only Computer B’s client keystore/truststore plus the token to Computer B. Preserve the backend and tools folder layout.",
        "Run the initial command on Computer B. It connects to Computer A over HTTPS with mutual TLS, obtains the fixed project challenge, validates the controlled evidence, and submits it to Computer A. Computer A then rotates its PQC keys and migrates its protected files.",
        "After Computer B reports success, sign in again on Computer A because self-healing revokes browser sessions. Reload this page to show the network record, migration timeline, new active key version, and audit events. Run the repeat command only after migration if you want to show the retired test session is rejected."
    ].forEach((text) => instructions.append(node("li", text)));
    setup.append(instructions);
    const host = status.remoteLabEnabled ? location.hostname : "<A-private-IP>";
    const port = status.remoteLabEnabled ? (location.port || "443") : "<chosen-port>";
    if (!status.remoteLabEnabled) {
        addCopyCommand("Computer A · create private lab credentials (replace placeholders)", "powershell -ExecutionPolicy Bypass -File tools\\create-remote-lab-certs.ps1 -ServerIp <A-private-IP> -OutputDirectory <private-output-directory>");
        addCopyCommand("Computer A · start a fresh allowlisted HTTPS vault (replace placeholders)", `powershell -ExecutionPolicy Bypass -File tools\\run-authorized-lab.ps1 -Role server -PrivateAddress <A-private-IP> -AllowedClientAddress <B-private-IP> -Port ${port} -VaultRoot data/vault-remote-demo`);
    }
    addCopyCommand("Computer B · initial remote event", `powershell -ExecutionPolicy Bypass -File tools\\run-authorized-lab.ps1 -Role client -ServerAddress ${host} -Port ${port} -Purpose initial`);
    addCopyCommand("Computer B · optional repeat after healing", `powershell -ExecutionPolicy Bypass -File tools\\run-authorized-lab.ps1 -Role client -ServerAddress ${host} -Port ${port} -Purpose repeat`);
    const boundary = node("p", "The network attack path is real: a second computer establishes TLS 1.3 with a client certificate and submits over the allowlisted network connection. The target and factorization evidence are deliberately fixed educational values; this is not arbitrary exploitation or a quantum attack. The resulting key rotation, file migration, re-signing, verification, and old-key retirement run on Computer A.", "notice-surface remote-boundary");
    setup.append(boundary);

    const timelinePanel = section("Self-healing on Computer A", "MILESTONES FROM PERSISTED BACKEND EVENTS");
    const refresh = node("button", "Refresh remote evidence", "button button-outline");
    refresh.type = "button";
    refresh.addEventListener("click", () => location.reload());
    timelinePanel.prepend(refresh);
    const stages = [
        ["Computer B connected over the authorized network", ["NETWORK_CONNECTION"]],
        ["Controlled test evidence accepted", ["NETWORK_ATTACK_DETECTED", "QUANTUM_THREAT"]],
        ["Self-healing started", ["SELF_HEALING_STARTED"]],
        ["New ML-KEM / ML-DSA keys generated", ["NEW_KEY_GENERATED", "NEW_PROTECTION_CREATED"]],
        ["Protected files migrated and verified", ["FILE_MIGRATED", "INTEGRITY_VERIFIED"]],
        ["Old PQC key version retired", ["KEY_REVOKED", "OLD_PROTECTION_REVOKED"]],
        ["Self-healing completed and verified", ["SELF_HEALING_COMPLETED"]]
    ];
    const seen = new Set(events.map((event) => event.action));
    const list = node("ol", undefined, "state-timeline remote-timeline");
    stages.forEach(([label, evidence], index) => {
        const event = events.find((entry) => evidence.includes(entry.action));
        const complete = Boolean(event);
        const item = node("li", undefined, `timeline-item${complete ? " complete" : ""}`);
        item.append(node("span", String(index + 1).padStart(2, "0"), "timeline-marker"));
        const copy = node("span", undefined, "timeline-copy");
        copy.append(node("strong", label), node("small", complete ? `Recorded · ${event.action}` : "Awaiting backend event"));
        if (complete && event.result) copy.append(node("small", String(event.result), "timeline-evidence"));
        item.append(copy);
        list.append(item);
    });
    timelinePanel.append(list);
    line("Remote mode", status.remoteLabEnabled ? "HTTPS + mutual TLS + allowlisted source IP" : "Disabled; server is loopback-only");
    line("Vault state", status.state);
    line("Active PQC key version", `v${status.keyVersion}`);
    line("Protected file records", status.fileCount);
    const netEvents = addEventTable(events, true);
    netEvents.prepend(node("p", "Computer B source IP, Computer A destination, fixed target, endpoint, and decision are recorded by the backend.", "section-copy"));
}
function addFiles(context, recovery) {
    const panel = section(recovery ? "Files available for verified recovery" : "Protected file records", "LIVE VAULT RECORDS");
    const recoveryStatus = recovery ? node("p", "Choose a file to compare its signed original SHA-256 with the recovered bytes.", "notice") : null;
    if (recoveryStatus) panel.append(recoveryStatus);
    const wrap = node("div", undefined, "table-wrap"); const table = document.createElement("table"), thead = document.createElement("thead"), head = document.createElement("tr");
    const labels = recovery ? ["FILE", "SIZE", "VERSION", "SIGNATURE", "INTEGRITY", "ACTION"] : ["FILE", "SIZE", "SHA-256 PREFIX", "VERSION", "SIGNATURE", "INTEGRITY"];
    labels.forEach((label) => head.append(node("th", label))); thead.append(head); table.append(thead);
    const tb = document.createElement("tbody");
    if (!context.files.length) { const tr = document.createElement("tr"), td = node("td", "No files are protected yet.", "empty-row"); td.colSpan = labels.length; tr.append(td); tb.append(tr); }
    context.files.forEach((file) => {
        const tr = document.createElement("tr");
        const values = recovery ? [file.filename, `${file.sizeBytes} bytes`, `v${file.version}`, file.signatureStatus, file.integrityStatus] : [file.filename, `${file.sizeBytes} bytes`, file.sha256Prefix, `v${file.version}`, file.signatureStatus, file.integrityStatus];
        values.forEach((value) => tr.append(node("td", String(value))));
        if (recovery) {
            const td = document.createElement("td"), button = node("button", "Verify and download", "button button-outline"); button.type = "button";
            button.addEventListener("click", async () => {
                button.disabled = true; vaultNotice(recoveryStatus, `Verifying ${file.filename} on the backend and comparing its recovered SHA-256…`);
                try {
                    const response = await fetch(`/api/vault/files/${encodeURIComponent(file.id)}/download`);
                    if (!response.ok) { const error = await response.json(); throw new Error(error.error || "Verified recovery failed."); }
                    const bytes = await response.arrayBuffer();
                    const digest = vaultHex(new Uint8Array(await crypto.subtle.digest("SHA-256", bytes)));
                    const matches = digest === file.sha256;
                    if (!matches) throw new Error(`Recovered SHA-256 mismatch. Expected ${file.sha256}; received ${digest}.`);
                    const objectUrl = URL.createObjectURL(new Blob([bytes], { type: file.contentType || "application/octet-stream" }));
                    const anchor = document.createElement("a"); anchor.href = objectUrl; anchor.download = file.filename; document.body.append(anchor); anchor.click(); anchor.remove();
                    setTimeout(() => URL.revokeObjectURL(objectUrl), 1000);
                    vaultNotice(recoveryStatus, `Original SHA-256: ${file.sha256} · Recovered SHA-256: ${digest} · MATCH · Backend signature, GCM tag, length, and hash verification passed.`, "success");
                } catch (error) { vaultNotice(recoveryStatus, error.message, "error"); }
                finally { button.disabled = false; }
            });
            td.append(button); tr.append(td);
        }
        tb.append(tr);
    });
    table.append(tb); wrap.append(table); panel.append(wrap);
}
async function addCryptographicArtifacts(context) {
    const panel = section("Inspect protected artifacts", "PERSISTED VALUES · SECRETS REMAIN HIDDEN");
    if (!context.files.length) { panel.append(node("p", "Upload a file to inspect its real cryptographic artifacts.", "notice")); return; }
    const select = document.createElement("select"); select.setAttribute("aria-label", "Select protected file");
    context.files.forEach((file) => { const option = document.createElement("option"); option.value = file.id; option.textContent = `${file.filename} · v${file.version}`; select.append(option); });
    const output = node("div", undefined, "artifact-inspector");
    const renderSelected = async () => {
        output.replaceChildren(node("p", "Loading signed metadata and cryptographic artifacts…", "notice"));
        try {
            const file = await vaultApi(`/api/vault/files/${encodeURIComponent(select.value)}`);
            output.replaceChildren();
            const groups = [
                ["File ingestion", [["Filename", file.filename], ["Type", file.contentType], ["Bytes", file.originalSize], ["SHA-256", file.sha256]]],
                ["AES-256-GCM", [["Status", "Encrypted"], ["Nonce", file.nonce], ["Ciphertext bytes", Math.max(0, file.ciphertextBytes - 16)], ["Authentication tag", file.authenticationTag], ["File key", "Random 256-bit key; never displayed; wrapped for storage"]]],
                ["ML-KEM-768", [["Provider", file.kem], ["Key version", `v${file.keyVersion}`], ["Encapsulation", file.encapsulation], ["Wrapped AES key", file.wrappedFileKey]]],
                ["ML-DSA-65", [["Canonical metadata", file.canonicalMetadata], ["Metadata SHA-256", file.metadataDigest], ["Signature bytes", file.signatureBytes], ["Verification", file.signatureValid ? "VALID" : "INVALID"]]],
                ["Secure storage", [["Record status", file.status], ["Integrity", file.integrityStatus], ["Created", file.createdAt], ["Ciphertext sample", file.ciphertextPreview]]]
            ];
            groups.forEach(([title, values]) => { const group = node("section", undefined, "artifact-group"); group.append(node("h3", title)); const dl = document.createElement("dl"); values.forEach(([label, value]) => { const row = document.createElement("div"); row.append(node("dt", label), node("dd", String(value ?? "—"))); dl.append(row); }); group.append(dl); output.append(group); });
        } catch (error) { output.replaceChildren(node("p", error.message, "notice notice-error")); }
    };
    select.addEventListener("change", renderSelected); panel.append(select, output); await renderSelected();
}
function addUploadForm() {
    const panel = section("Protect a file", "UPLOAD · HASH · ENCRYPT · WRAP · SIGN");
    const form = document.createElement("form"); form.id = "workflowUploadForm";
    const steps = node("ol", undefined, "upload-steps");
    ["Upload", "Hash", "Encrypt", "Protect", "Sign", "Store"].forEach((label, index) => { const item = node("li", undefined, "upload-step"); item.append(node("b", `0${index + 1}`), node("span", label)); steps.append(item); });
    const label = node("label", undefined, "file-picker"); label.htmlFor = "workflowFile";
    label.append(node("span", "+", "picker-mark")); const copy = node("span");
    copy.append(node("strong", "Drop a file here or choose one"), node("small", "Maximum 16 MiB · file bytes are processed by Java"));
    label.append(copy, node("span", "Browse", "picker-action"));
    const input = document.createElement("input"); input.type = "file"; input.id = "workflowFile"; input.required = true; input.className = "workflow-upload-input";
    const info = node("p", "Select a file to calculate SHA-256 locally before sending it to the Java vault.", "notice");
    const digest = node("code", "No file selected", "workflow-digest");
    const button = node("button", "Protect and store file", "button button-primary"); button.type = "submit"; button.disabled = true;
    const notice = node("p", "Ready.", "notice"); notice.id = "workflowUploadNotice";
    form.append(steps, label, input, info, digest, button, notice); panel.append(form);
    let selectedHash = "";
    label.addEventListener("dragover", (event) => { event.preventDefault(); label.classList.add("is-dragging"); });
    label.addEventListener("dragleave", () => label.classList.remove("is-dragging"));
    label.addEventListener("drop", (event) => {
        event.preventDefault(); label.classList.remove("is-dragging");
        const selected = event.dataTransfer?.files?.[0]; if (!selected) return;
        const transfer = new DataTransfer(); transfer.items.add(selected); input.files = transfer.files;
        input.dispatchEvent(new Event("change", { bubbles: true }));
    });
    input.addEventListener("change", async () => {
        const file = input.files?.[0]; button.disabled = true; selectedHash = "";
        if (!file) { digest.textContent = "No file selected"; return; }
        if (file.size > 16 * 1024 * 1024) { vaultNotice(notice, "Maximum upload size is 16 MiB.", "error"); digest.textContent = "File exceeds the service limit"; return; }
        digest.textContent = "Calculating SHA-256…";
        try { selectedHash = vaultHex(new Uint8Array(await crypto.subtle.digest("SHA-256", await file.arrayBuffer()))); digest.textContent = `${file.name} · ${file.size} bytes · SHA-256 ${selectedHash}`; button.disabled = false; }
        catch { digest.textContent = "Browser SHA-256 is unavailable"; vaultNotice(notice, "This browser could not calculate SHA-256.", "error"); }
    });
    form.addEventListener("submit", async (event) => {
        event.preventDefault(); const file = input.files?.[0]; if (!file || !selectedHash) return;
        button.disabled = true; button.textContent = "Encrypting and storing…"; vaultNotice(notice, "Java is hashing, encrypting, encapsulating, signing, and storing this file.");
        try {
            const formData = new FormData(); formData.append("file", file, file.name);
            const record = await vaultApi("/api/vault/upload", { method: "POST", body: formData });
            const matches = record.sha256 === selectedHash;
            vaultNotice(notice, matches ? `Stored and protected ${record.filename}; browser and server SHA-256 match (${selectedHash}).` : "The file was stored, but the browser and server SHA-256 values differed. Inspect the record before relying on it.", matches ? "success" : "error");
            if (matches) {
                addLine("Upload result", `${record.filename} · ${record.protection || "AES-256-GCM"} · ${record.signatureAlgorithm || "ML-DSA-65"}`);
                if (record.performanceMs) addLine("Measured backend time (ms)", Object.entries(record.performanceMs).map(([name, value]) => `${name}: ${value}`).join(" · "));
                steps.querySelectorAll(".upload-step").forEach((step) => step.classList.add("complete"));
            }
        } catch (error) { vaultNotice(notice, error.message, "error"); }
        finally { button.disabled = false; button.textContent = "Protect and store file"; }
    });
}
async function render() {
    const view = new URLSearchParams(location.search).get("view") || "monitor"; const [eyebrow, title, intro] = views[view] || views.monitor;
    document.body.dataset.vaultPage = view; document.title = `${title} · VaultIQ`;
    document.querySelector("#viewEyebrow").textContent = eyebrow; document.querySelector("#viewTitle").textContent = title; document.querySelector("#viewIntro").textContent = intro;
    const [context, audit, status] = await Promise.all([vaultApi("/api/vault/security-context"), vaultApi("/api/vault/audit"), vaultApi("/api/vault/status")]);
    document.querySelector("#viewState").textContent = `${status.state} · KEY V${status.keyVersion}`;
    if (view === "upload") addUploadForm();
    if (view === "process") {
        const flow = section("Protection sequence", "REAL OPERATIONS · JAVA BACKEND");
        [["SHA-256", "Java independently hashes the received file bytes."], ["AES-256-GCM", "A random 256-bit file key encrypts bytes with an authenticated GCM tag."], ["ML-KEM-768", "The JDK KEM establishes a secret used to wrap the AES file key."], ["ML-DSA-65", "Canonical file metadata is signed; recovery verifies the signature."], ["Verified recovery", "Signature, GCM tag, recovered length, and SHA-256 are checked before download."]].forEach(([name, description]) => { const item = node("div", undefined, "workflow-row"); item.append(node("b", name), node("span", description)); flow.append(item); });
        addFiles(context, false);
        await addCryptographicArtifacts(context);
        const timings = context.recentEvents.filter((event) => event.action.startsWith("PERFORMANCE_"));
        const metrics = section("Measured operation times", "RECORDED DURATIONS · MILLISECONDS");
        if (!timings.length) metrics.append(node("p", "No measured operation timings are recorded yet. Upload or recover a file to populate this section.", "notice"));
        else timings.forEach((event) => { const row = node("div", undefined, "workflow-row"); row.append(node("b", `${event.action.replaceAll("PERFORMANCE_", "")} · ${event.record || "vault"}`), node("span", event.result)); metrics.append(row); });
    }
    if (view === "pqc") {
        const keys = await vaultApi("/api/vault/key-status");
        line("ML-KEM-768", `${keys.kemProvider} · public key ${keys.kemPublicKeyBytes} bytes · used to wrap the per-file AES key`);
        line("ML-DSA-65", `${keys.signatureProvider} · public key ${keys.signaturePublicKeyBytes} bytes · signs canonical file metadata`);
        line("Active version", `v${keys.keyVersion} · privateKeysExported=${keys.privateKeysExported}`);
        line("Live cryptographic test", "pqc.html runs actual JDK ML-KEM encapsulation/decapsulation and ML-DSA signing/verification using the active vault key version.");
    }
    if (view === "monitor") {
        line("Vault", status.state); line("Protected files", context.fileCount); line("Active key", `v${context.activeKeyVersion}`); line("Self-healing", context.selfHealingStatus);
        const eventPanel = addEventTable(audit.events); const refreshEvents = node("button", "Refresh observed events", "button button-outline");
        refreshEvents.type = "button"; refreshEvents.addEventListener("click", () => location.reload()); eventPanel.prepend(refreshEvents);
    }
    if (view === "attack") {
        const healed = status.state === "PQC_ACTIVE";
        const purpose = healed ? "repeat" : "initial";
        const launchPanel = section("Choose an attack lab", "TWO DISTINCT DEMONSTRATIONS");
        const launchIntro = node("p", healed
            ? "The initial walkthrough already completed and rotated the vault to key v" + status.keyVersion + ". Start the repeat walkthrough to demonstrate that the retired test session is rejected."
            : "Start the local walkthrough in this browser, or open the setup guide for a real Computer B to Computer A connection.", "section-copy");
        const launchActions = node("div", undefined, "attack-lab-actions");
        const messageForm = node("div", undefined, "attack-message");
        const messageLabel = node("label", "Message for the RSA walkthrough");
        messageLabel.htmlFor = "attackMessage";
        const messageInput = node("textarea");
        messageInput.id = "attackMessage";
        messageInput.rows = 3;
        messageInput.maxLength = 3000;
        messageInput.placeholder = "Enter a short message using basic English characters";
        messageInput.value = sessionStorage.getItem("userMessage") || "HELLO PQC";
        const messageHelp = node("p", "Your message is passed into the RSA walkthrough. Use characters with values 0–255 (Latin-1).", "attack-message-help");
        messageForm.append(messageLabel, messageInput, messageHelp);
        const localButton = node("button", healed ? "Start repeat RSA / Shor walkthrough" : "Start local RSA / Shor walkthrough", "button button-primary");
        localButton.type = "button";
        const launchStatus = node("p", "", "notice notice-error");
        launchStatus.id = "attackLaunchStatus";
        launchStatus.setAttribute("role", "status");
        launchStatus.hidden = true;
        localButton.addEventListener("click", async () => {
            const enteredMessage = messageInput.value;
            const unsupported = Array.from(enteredMessage).find((character) => character.codePointAt(0) > 255);
            if (!enteredMessage.trim() || unsupported) {
                launchStatus.textContent = unsupported
                    ? "Use characters with values 0–255 (Latin-1) for this small RSA walkthrough."
                    : "Enter a message before starting the walkthrough.";
                launchStatus.hidden = false;
                return;
            }
            localButton.disabled = true;
            localButton.textContent = "Preparing demo…";
            try {
                const session = await vaultApi("/api/vault/attack-session", {
                    method: "POST",
                    headers: { "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8" },
                    body: new URLSearchParams({ purpose })
                });
                sessionStorage.setItem("vaultAttackMode", purpose);
                sessionStorage.setItem("vaultAttackSession", session.sessionId);
                sessionStorage.setItem("userMessage", enteredMessage);
                location.href = "rsa.html";
            } catch (error) {
                localButton.disabled = false;
                localButton.textContent = healed ? "Start repeat RSA / Shor walkthrough" : "Start local RSA / Shor walkthrough";
                launchStatus.textContent = error.message;
                launchStatus.hidden = false;
            }
        });
        const remoteLink = node("a", "Open two-computer lab guide", "button button-outline");
        remoteLink.href = "workflow.html?view=remote";
        launchActions.append(localButton, remoteLink);
        launchPanel.append(launchIntro, messageForm, launchActions, launchStatus);
        line("Network lab mode", status.remoteLabEnabled ? "Enabled · HTTPS with mutual TLS and IP allowlist" : "Disabled · server is loopback-only");
        line("Remote network lab", "Requires explicit HTTPS/mTLS configuration, an allowlisted Computer B IP, and a one-use bearer token. Use the guide above to configure it.");
        line("Local walkthrough", "Uses a fixed educational RSA target. The Java backend validates evidence before any vault migration.");
        line("Target restriction", "The client validates only project target PROJECT_RSA_3233 (N=3233), and submits only to /api/lab/*. No arbitrary host or scanning mode exists.");
        line("Teaching boundary", "TCP/TLS exchange is real network traffic. Period finding and factor recovery are classical calculations, not a quantum computer or RSA-2048 attack.");
        const lessons = section("Preserved classical and quantum teaching modules", "FIXED SMALL RSA TARGET · EDUCATIONAL SIMULATION");
        [["Classical RSA", "rsa.html"], ["Shor calculation", "quantum.html"], ["Real PQC operations", "pqc.html"]].forEach(([label, href]) => { const link = node("a", label, "button button-outline"); link.href = href; lessons.append(link); });
        const attackPanel = addEventTable(audit.events, true); const refreshAttack = node("button", "Refresh network evidence", "button button-outline");
        refreshAttack.type = "button"; refreshAttack.addEventListener("click", () => location.reload()); attackPanel.prepend(refreshAttack);
    }
    if (view === "remote") addRemoteDemo(status, audit.events);
    if (view === "healing") {
        const stages = [
            ["Controlled test evidence accepted", ["QUANTUM_THREAT"]],
            ["Self-healing started", ["SELF_HEALING_STARTED"]],
            ["Previous test sessions invalidated", ["RSA_TEST_PATH_REVOKED"]],
            ["New PQC keys created", ["NEW_KEY_GENERATED", "NEW_PROTECTION_CREATED"]],
            ["File metadata re-signed", ["SIGNATURE_RECREATED"]],
            ["File migrated and verified", ["FILE_MIGRATED", "INTEGRITY_VERIFIED"]],
            ["Old PQC keys retired", ["OLD_PROTECTION_REVOKED", "KEY_REVOKED"]],
            ["Migration completed", ["SELF_HEALING_COMPLETED"]]
        ];
        const panel = section("Migration progress", "BACKEND EVENT EVIDENCE");
        const list = node("ol", undefined, "state-timeline");
        stages.forEach(([label, actions], index) => {
            const event = audit.events.find((entry) => actions.includes(entry.action));
            const complete = Boolean(event);
            const item = node("li", undefined, `timeline-item${complete ? " complete" : ""}`);
            item.append(node("span", String(index + 1).padStart(2, "0"), "timeline-marker"));
            const copy = node("span", undefined, "timeline-copy");
            copy.append(node("strong", label), node("small", complete ? `Recorded · ${event.action}` : "Awaiting backend event"));
            if (complete && event.result) copy.append(node("small", String(event.result), "timeline-evidence"));
            item.append(copy);
            list.append(item);
        });
        panel.append(list);
        line("Current protection", context.activeProtection); line("Current signature status", context.signatureStatus); line("Integrity evidence", context.integrityStatus);
        const oldProtection = audit.events.find((event) => event.action === "OLD_PROTECTION_REVOKED");
        line("Old-key retirement evidence", oldProtection ? oldProtection.result : "No old-key retirement event recorded.");
    }
    if (view === "recovery") addFiles(context, true);
}
window.addEventListener("vault:ready", (event) => { if (event.detail.unlocked) render().catch((error) => vaultNotice(document.querySelector("#unlockNotice"), error.message, "error")); });
