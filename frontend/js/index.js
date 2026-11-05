const tabButtons = Array.from(document.querySelectorAll("[data-tab]"));
const tabPanels = Array.from(document.querySelectorAll("[data-panel]"));
const messageInput = document.getElementById("message");
const protectForm = document.getElementById("protectForm");
const protectButton = document.getElementById("protectButton");
const protectNotice = document.getElementById("protectNotice");
const packagePanel = document.getElementById("packagePanel");
const recoveryNotice = document.getElementById("recoveryNotice");
const recoveredPanel = document.getElementById("recoveredPanel");
let activePackage = null;

async function request(path, form = new URLSearchParams()) {
    const response = await fetch(path, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8" },
        body: form
    });
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || "The request could not be completed.");
    return result;
}

function setNotice(element, text, kind = "") {
    element.textContent = text;
    element.classList.toggle("is-error", kind === "error");
    element.classList.toggle("is-success", kind === "success");
}

function selectTab(name) {
    tabButtons.forEach((button) => {
        const selected = button.dataset.tab === name;
        button.classList.toggle("is-active", selected);
        button.setAttribute("aria-selected", String(selected));
        button.tabIndex = selected ? 0 : -1;
    });
    tabPanels.forEach((panel) => {
        panel.hidden = panel.dataset.panel !== name;
    });
}

tabButtons.forEach((button, index) => {
    button.addEventListener("click", () => selectTab(button.dataset.tab));
    button.addEventListener("keydown", (event) => {
        if (event.key !== "ArrowLeft" && event.key !== "ArrowRight") return;
        event.preventDefault();
        const direction = event.key === "ArrowRight" ? 1 : -1;
        const next = (index + direction + tabButtons.length) % tabButtons.length;
        tabButtons[next].focus();
        selectTab(tabButtons[next].dataset.tab);
    });
});

messageInput.addEventListener("input", () => {
    document.getElementById("characterCount").textContent = `${messageInput.value.length.toLocaleString()} / 16,000`;
});

protectForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    protectButton.disabled = true;
    protectButton.firstElementChild.textContent = "Protecting...";
    setNotice(protectNotice, "Generating ephemeral keys and protecting the message...");
    try {
        const result = await request("/api/protect", new URLSearchParams(new FormData(protectForm)));
        activePackage = result;
        document.getElementById("packageId").textContent = result.id;
        document.getElementById("packageVersion").textContent = String(result.version);
        document.getElementById("operationTime").textContent = `${result.elapsedMs} ms`;
        document.getElementById("encapsulation").textContent = result.encapsulation;
        document.getElementById("ciphertext").textContent = result.ciphertext;
        document.getElementById("signatureSize").textContent = `${result.signatureBytes.toLocaleString()} bytes`;
        document.getElementById("activeRecord").textContent = result.id;
        document.getElementById("activeVersion").textContent = String(result.version);
        document.getElementById("verifyButton").disabled = false;
        document.getElementById("tamperButton").disabled = false;
        document.getElementById("rotateButton").disabled = false;
        packagePanel.hidden = false;
        recoveredPanel.hidden = true;
        setNotice(protectNotice, "Protected with ML-KEM-768, AES-256-GCM, and ML-DSA-65.", "success");
        setNotice(recoveryNotice, "Package ready. Choose a verification or recovery drill.");
        await refreshEvents();
    } catch (error) {
        setNotice(protectNotice, error.message, "error");
    } finally {
        protectButton.disabled = false;
        protectButton.firstElementChild.textContent = "Protect message";
    }
});

async function recover(simulateIncident) {
    if (!activePackage) return;
    const verifyButton = document.getElementById("verifyButton");
    const tamperButton = document.getElementById("tamperButton");
    const rotateButton = document.getElementById("rotateButton");
    verifyButton.disabled = true;
    tamperButton.disabled = true;
    rotateButton.disabled = true;
    setNotice(recoveryNotice, simulateIncident ? "Running the incident drill and rotating the KEM key..." : "Authenticating and decrypting the protected package...");
    try {
        const result = await request("/api/recover", new URLSearchParams({
            id: activePackage.id,
            simulateIncident: String(simulateIncident)
        }));
        document.getElementById("recoveredMessage").textContent = result.message;
        document.getElementById("signatureResult").textContent = result.signatureValid ? "SIGNATURE VALID" : "SIGNATURE INVALID";
        document.getElementById("rotationResult").textContent = result.rotated
            ? `Incident was explicitly simulated. A fresh ML-KEM key was issued; package is now at version ${result.version}.`
            : `Message restored and authenticated in ${result.elapsedMs} ms. Key version was not changed.`;
        document.getElementById("activeVersion").textContent = String(result.version);
        document.getElementById("packageVersion").textContent = String(result.version);
        recoveredPanel.hidden = false;
        setNotice(recoveryNotice, result.rotated ? "Recovery completed; key rotation verified." : "Recovery and signature verification completed.", "success");
        await refreshEvents();
    } catch (error) {
        setNotice(recoveryNotice, error.message, "error");
    } finally {
        verifyButton.disabled = !activePackage;
        tamperButton.disabled = !activePackage;
        rotateButton.disabled = !activePackage;
    }
}

document.getElementById("verifyButton").addEventListener("click", () => recover(false));
document.getElementById("rotateButton").addEventListener("click", () => recover(true));

document.getElementById("tamperButton").addEventListener("click", async () => {
    if (!activePackage) return;
    const controls = ["verifyButton", "tamperButton", "rotateButton"];
    controls.forEach((id) => { document.getElementById(id).disabled = true; });
    setNotice(recoveryNotice, "Flipping one bit in a temporary ciphertext copy and checking authentication...");
    try {
        const result = await request("/api/tamper", new URLSearchParams({ id: activePackage.id }));
        setNotice(recoveryNotice, result.message, result.blocked ? "success" : "error");
        await refreshEvents();
    } catch (error) {
        setNotice(recoveryNotice, error.message, "error");
    } finally {
        controls.forEach((id) => { document.getElementById(id).disabled = !activePackage; });
    }
});

async function refreshEvents() {
    try {
        const response = await fetch("/api/events");
        if (!response.ok) return;
        const result = await response.json();
        const list = document.getElementById("eventList");
        list.replaceChildren();
        document.getElementById("eventCount").textContent = String(result.events.length);
        if (!result.events.length) {
            const empty = document.createElement("li");
            empty.className = "event-empty";
            empty.textContent = "No operations yet.";
            list.append(empty);
            return;
        }
        result.events.forEach((event) => {
            const item = document.createElement("li");
            const top = document.createElement("div");
            top.className = "event-topline";
            const action = document.createElement("span");
            action.className = "event-action";
            action.textContent = event.action.replaceAll("_", " ");
            const time = document.createElement("time");
            time.className = "event-time";
            time.dateTime = event.time;
            time.textContent = new Date(event.time).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
            top.append(action, time);
            const detail = document.createElement("span");
            detail.className = "event-detail";
            detail.textContent = `Record ${event.record.slice(0, 8)}... / v${event.version} / ${event.result}`;
            item.append(top, detail);
            list.append(item);
        });
    } catch {
        // The status check reports when the backend is unavailable.
    }
}

document.getElementById("benchmarkButton").addEventListener("click", async (event) => {
    const button = event.currentTarget;
    button.disabled = true;
    button.firstElementChild.textContent = "Measuring...";
    setNotice(document.getElementById("benchmarkNotice"), "Running three rounds for each algorithm group...");
    try {
        const result = await request("/api/benchmark");
        const metrics = [result.mlKem.averageMs, result.mlDsa.averageMs, result.rsa.averageMs];
        const max = Math.max(...metrics, 0.01);
        document.getElementById("kemMetric").textContent = `${result.mlKem.averageMs} ms`;
        document.getElementById("dsaMetric").textContent = `${result.mlDsa.averageMs} ms`;
        document.getElementById("rsaMetric").textContent = `${result.rsa.averageMs} ms`;
        document.getElementById("kemBar").style.width = `${Math.max(5, metrics[0] / max * 100)}%`;
        document.getElementById("dsaBar").style.width = `${Math.max(5, metrics[1] / max * 100)}%`;
        document.getElementById("rsaBar").style.width = `${Math.max(5, metrics[2] / max * 100)}%`;
        document.getElementById("kemPublicSize").textContent = `${result.mlKem.publicKeyBytes.toLocaleString()} B`;
        document.getElementById("kemEncapSize").textContent = `${result.mlKem.encapsulationBytes.toLocaleString()} B`;
        document.getElementById("dsaSignatureSize").textContent = `${result.mlDsa.signatureBytes.toLocaleString()} B`;
        document.getElementById("rsaPublicSize").textContent = `${result.rsa.publicKeyBytes.toLocaleString()} B`;
        document.getElementById("benchmarkResults").hidden = false;
        setNotice(document.getElementById("benchmarkNotice"), `Completed ${result.rounds} rounds for each algorithm group.`, "success");
    } catch (error) {
        setNotice(document.getElementById("benchmarkNotice"), error.message, "error");
    } finally {
        button.disabled = false;
        button.firstElementChild.textContent = "Run benchmark";
    }
});

async function checkServer() {
    const status = document.getElementById("serverStatus");
    try {
        const response = await fetch("/api/status");
        if (!response.ok) throw new Error("Server not ready");
        const result = await response.json();
        status.classList.add("is-online");
        status.classList.remove("is-offline");
        status.lastChild.textContent = "ONLINE";
        document.getElementById("serverDetail").textContent = `JDK ${result.javaVersion} · ${result.kemProvider} · ${result.signatureProvider}`;
        document.getElementById("footerJava").textContent = `JDK ${result.javaVersion} · ${result.kem} / ${result.signature}`;
    } catch {
        status.classList.add("is-offline");
        status.classList.remove("is-online");
        status.lastChild.textContent = "OFFLINE";
        document.getElementById("serverDetail").textContent = "Start the local server with run.bat.";
    }
}

selectTab("secure");
checkServer();
refreshEvents();