let selectedFile = null;
let selectedRecordId = null;

function addEvidenceList(selector, entries) {
    const list = document.querySelector(selector);
    list.replaceChildren();
    entries.forEach(([label, value]) => {
        const row = document.createElement("div");
        const key = document.createElement("dt");
        const content = document.createElement("dd");
        key.textContent = label;
        content.textContent = value ?? "—";
        row.append(key, content);
        list.append(row);
    });
}

async function refreshFiles() {
    const result = await vaultApi("/api/vault/files");
    const body = document.querySelector("#fileRows");
    body.replaceChildren();
    if (!result.files.length) {
        const row = document.createElement("tr");
        const empty = document.createElement("td"); empty.colSpan = 10; empty.className = "empty-row"; empty.textContent = "No protected files yet.";
        row.append(empty); body.append(row); return;
    }
    result.files.forEach((file) => {
        const row = document.createElement("tr");
        [file.filename, file.contentType || "application/octet-stream", vaultBytesLabel(file.originalSize),
            file.sha256.slice(0, 12) + "…", file.protection, "v" + file.keyVersion,
            file.signatureValid ? "VALID" : "INVALID", file.integrityStatus, file.status].forEach((value, index) => {
            const cell = document.createElement("td"); cell.textContent = value;
            if (index === 3) cell.className = "hash-cell";
            if (index === 6) cell.className = file.signatureValid ? "integrity-good" : "integrity-bad";
            if (index === 7) cell.className = file.integrityStatus === "VERIFIED" ? "integrity-good" : "";
            row.append(cell);
        });
        const action = document.createElement("td"); action.className = "file-row-actions";
        const view = document.createElement("button"); view.type = "button"; view.className = "file-action"; view.textContent = "View";
        view.addEventListener("click", async () => { await showFile(file.id); document.querySelector("#fileDetailPanel").scrollIntoView({ behavior: "smooth", block: "start" }); });
        const recover = document.createElement("button"); recover.type = "button"; recover.className = "file-action"; recover.textContent = "Recover";
        recover.addEventListener("click", async () => { await showFile(file.id); document.querySelector("#fileDetailPanel").scrollIntoView({ behavior: "smooth", block: "start" }); await recoverFile(file.id); });
        const download = document.createElement("a"); download.className = "file-action"; download.textContent = "Download";
        download.href = `/api/vault/files/${encodeURIComponent(file.id)}/download`;
        const details = document.createElement("button"); details.type = "button"; details.className = "file-action"; details.textContent = "Details";
        details.addEventListener("click", async () => { await showFile(file.id); document.querySelector(".canonical-details").open = true; });
        const remove = document.createElement("button"); remove.type = "button"; remove.className = "file-action file-action-danger"; remove.textContent = "Delete";
        remove.addEventListener("click", async () => {
            if (!confirm(`Permanently delete ${file.filename} and its protected backup?`)) return;
            remove.disabled = true;
            try {
                await vaultApi(`/api/vault/files/${encodeURIComponent(file.id)}`, { method: "DELETE" });
                if (selectedRecordId === file.id) {
                    selectedRecordId = null;
                    document.querySelector("#fileDetailPanel").hidden = true;
                }
                await refreshFiles();
            } catch (error) {
                alert(error.message);
            } finally {
                remove.disabled = false;
            }
        });
        action.append(view, recover, download, details, remove); row.append(action); body.append(row);
    });
}

async function recoverFile(id) {
    const notice = document.querySelector("#fileActionNotice");
    if (notice) vaultNotice(notice, "Verifying the signature, AES-GCM tag, and SHA-256 before recovery…");
    try {
        const response = await fetch(`/api/vault/files/${encodeURIComponent(id)}/download`);
        if (!response.ok) throw new Error((await response.json()).error || "File recovery verification failed.");
        const blob = await response.blob();
        const filename = (response.headers.get("content-disposition") || "").match(/filename\*=UTF-8''([^;]+)/i);
        const objectUrl = URL.createObjectURL(blob);
        const anchor = document.createElement("a"); anchor.href = objectUrl;
        anchor.download = filename ? decodeURIComponent(filename[1]) : "recovered-file";
        document.body.append(anchor); anchor.click(); anchor.remove();
        setTimeout(() => URL.revokeObjectURL(objectUrl), 1000);
        if (notice) vaultNotice(notice, `Verified and recovered ${anchor.download} (${vaultBytesLabel(blob.size)}).`, "success");
    } catch (error) { if (notice) vaultNotice(notice, error.message, "error"); else alert(error.message); }
}
async function showFile(id) {
    const file = await vaultApi(`/api/vault/files/${encodeURIComponent(id)}`);
    selectedRecordId = file.id;
    document.querySelector("#fileDetailPanel").hidden = false;
    document.querySelector("#detailFilename").textContent = file.filename;
    document.querySelector("#detailSignatureStatus").textContent = file.signatureValid ? "SIGNATURE VALID" : "SIGNATURE INVALID";
    document.querySelector("#detailSignatureStatus").classList.toggle("invalid", !file.signatureValid);
    addEvidenceList("#fileMetadata", [["Filename", file.filename], ["File type", file.contentType], ["Size", vaultBytesLabel(file.originalSize)], ["Original SHA-256", file.sha256], ["Key version", `v${file.keyVersion}`], ["Record status", file.status], ["Integrity evidence", file.integrityStatus], ["Stored at", file.createdAt]]);
    addEvidenceList("#aesEvidence", [["Algorithm", file.protection], ["Key", "Random 256-bit file key · wrapped"], ["Nonce / IV", file.nonce], ["Ciphertext bytes", file.ciphertextBytes - 16], ["GCM tag", file.authenticationTag]]);
    addEvidenceList("#kemEvidence", [["Algorithm", file.kem], ["Purpose", "Wrap the AES file key only"], ["Key version", `v${file.keyVersion}`], ["Encapsulation", `${file.encapsulation.slice(0, 42)}…`]]);
    addEvidenceList("#signatureEvidence", [["Algorithm", file.signatureAlgorithm], ["Signed metadata SHA-256", file.metadataDigest], ["Signature size", `${file.signatureBytes.toLocaleString()} bytes`], ["Verification", file.signatureValid ? "VALID" : "INVALID"]]);
    document.querySelector("#canonicalMetadata").textContent = file.canonicalMetadata;
    const artifacts = document.querySelector("#artifactList");
    artifacts.replaceChildren();
    [["KEM encapsulation", file.encapsulation], ["Wrapped AES key", file.wrappedFileKey], ["Ciphertext sample", file.ciphertextPreview], ["GCM tag", file.authenticationTag], ["ML-DSA signature", file.signature]].forEach(([name, value]) => {
        const row = document.createElement("div");
        const label = document.createElement("span");
        const code = document.createElement("code");
        label.textContent = name;
        code.textContent = value;
        row.append(label, code);
        artifacts.append(row);
    });
    document.querySelector("#downloadFile").href = `/api/vault/files/${encodeURIComponent(id)}/download`;
}

document.querySelector("#fileInput").addEventListener("change", async (event) => {
    selectedFile = event.target.files[0] || null;
    document.querySelector("#protectFileButton").disabled = !selectedFile;
    document.querySelector("#selectedFile").hidden = !selectedFile;
    document.querySelector("#uploadProcess").hidden = !selectedFile;
    if (!selectedFile) return;
    document.querySelector("#filePickerTitle").textContent = selectedFile.name;
    document.querySelector("#filePickerHint").textContent = "Selected file · calculating SHA-256 in browser";
    document.querySelector("#selectedName").textContent = selectedFile.name;
    document.querySelector("#selectedSize").textContent = vaultBytesLabel(selectedFile.size);
    document.querySelector("#selectedType").textContent = selectedFile.type || "application/octet-stream";
    document.querySelector("#selectedHash").textContent = "Calculating…";
    try {
        const digest = await crypto.subtle.digest("SHA-256", await selectedFile.arrayBuffer());
        document.querySelector("#selectedHash").textContent = vaultHex(new Uint8Array(digest));
        document.querySelector("#ingestionStatus").textContent = "HASHED";
        document.querySelector("#ingestionStatus").parentElement.classList.add("done");
        vaultNotice(document.querySelector("#uploadNotice"), "Browser digest ready. Java independently calculates the digest during upload.", "success");
    } catch {
        document.querySelector("#selectedHash").textContent = "Unavailable";
        vaultNotice(document.querySelector("#uploadNotice"), "Browser SHA-256 could not be calculated.", "error");
    }
});

document.querySelector("#uploadForm").addEventListener("submit", async (event) => {
    event.preventDefault();
    if (!selectedFile) return;
    if (selectedFile.size === 0 || selectedFile.size > 16 * 1024 * 1024) {
        vaultNotice(document.querySelector("#uploadNotice"), "Choose a non-empty file no larger than 16 MiB.", "error");
        return;
    }
    const button = document.querySelector("#protectFileButton");
    button.disabled = true;
    button.firstChild.textContent = "Protecting… ";
    ["aesStatus", "kemStatus", "signatureStatus"].forEach((id) => { document.querySelector(`#${id}`).textContent = "RUNNING"; });
    vaultNotice(document.querySelector("#uploadNotice"), "Sending to the local Java backend for encryption, KEM key wrapping, and metadata signing…");
    try {
        const form = new FormData();
        form.append("file", selectedFile, selectedFile.name);
        const result = await vaultApi("/api/vault/upload", { method: "POST", body: form });
        if (result.sha256 !== document.querySelector("#selectedHash").textContent) {
            throw new Error("Browser/server SHA-256 mismatch; inspect the file before continuing.");
        }
        ["aesStatus", "kemStatus", "signatureStatus"].forEach((id) => {
            const node = document.querySelector(`#${id}`);
            node.textContent = "COMPLETE";
            node.parentElement.classList.add("done");
        });
        vaultNotice(document.querySelector("#uploadNotice"), "Protected and signed. Independent SHA-256 values match.", "success");
        await refreshFiles();
        await showFile(result.id);
    } catch (error) {
        vaultNotice(document.querySelector("#uploadNotice"), error.message, "error");
    } finally {
        button.disabled = !selectedFile;
        button.firstChild.textContent = "Protect and store file ";
    }
});

document.querySelector("#refreshFiles").addEventListener("click", () => refreshFiles().catch((error) => vaultNotice(document.querySelector("#uploadNotice"), error.message, "error")));

document.querySelector("#downloadFile").addEventListener("click", async (event) => {
    if (!selectedRecordId) return;
    event.preventDefault();
    await recoverFile(selectedRecordId);
});

const fileDropZone = document.querySelector(".file-picker");
["dragenter", "dragover"].forEach((name) => fileDropZone.addEventListener(name, (event) => {
    event.preventDefault(); fileDropZone.classList.add("is-dragging");
}));
["dragleave", "drop"].forEach((name) => fileDropZone.addEventListener(name, (event) => {
    event.preventDefault(); fileDropZone.classList.remove("is-dragging");
}));
fileDropZone.addEventListener("drop", (event) => {
    const droppedFile = event.dataTransfer?.files?.[0];
    if (!droppedFile) return;
    const transfer = new DataTransfer(); transfer.items.add(droppedFile);
    const input = document.querySelector("#fileInput"); input.files = transfer.files;
    input.dispatchEvent(new Event("change", { bubbles: true }));
});
document.querySelector("#tamperFile").addEventListener("click", async () => {
    if (!selectedRecordId) return;
    const button = document.querySelector("#tamperFile");
    button.disabled = true;
    try {
        const result = await vaultApi(`/api/vault/files/${encodeURIComponent(selectedRecordId)}/tamper`, { method: "POST" });
        vaultNotice(document.querySelector("#fileActionNotice"), `Tampering detected; verified backup restored. SHA-256 ${result.sha256}.`, "success");
        await showFile(selectedRecordId);
    } catch (error) {
        vaultNotice(document.querySelector("#fileActionNotice"), error.message, "error");
    } finally {
        button.disabled = false;
    }
});

window.addEventListener("vault:ready", (event) => {
    if (event.detail.unlocked) refreshFiles().catch((error) => vaultNotice(document.querySelector("#uploadNotice"), error.message, "error"));
});
