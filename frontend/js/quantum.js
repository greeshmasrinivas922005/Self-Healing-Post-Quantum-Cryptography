// ============================================================
// SHOR'S ALGORITHM - QUANTUM ATTACK SIMULATION
// ============================================================


// ------------------------------------------------------------
// RSA TARGET
// ------------------------------------------------------------

const rsaModulus = 3233;


// ------------------------------------------------------------
// CHECK SELF-HEALING TRIGGER
// ------------------------------------------------------------

const ciphertextAccessAttempt =
    sessionStorage.getItem("ciphertextAccessAttempt") === "true";


// ------------------------------------------------------------
// SHOR'S ALGORITHM PARAMETERS
//
// Educational simulation:
//
// N = 3233
// a = 3
// r = 260
//
// 3^260 mod 3233 = 1
//
// r is even:
//
// factor 1 = gcd(3^130 - 1, 3233) = 61
// factor 2 = gcd(3^130 + 1, 3233) = 53
//
// Therefore:
//
// 3233 = 61 × 53
// ------------------------------------------------------------

const quantumN = 3233;
const quantumA = 3;
const knownPeriod = 260;


// ------------------------------------------------------------
// DOM ELEMENTS
// ------------------------------------------------------------

const rsaModulusElement =
    document.getElementById("rsaModulus");

const factorPElement =
    document.getElementById("factorP");

const factorQElement =
    document.getElementById("factorQ");

const quantumNElement =
    document.getElementById("quantumN");

const quantumAElement =
    document.getElementById("quantumA");

const gcdResultElement =
    document.getElementById("gcdResult");

const periodResultElement =
    document.getElementById("periodResult");

const startShorButton =
    document.getElementById("startShorButton");

const step1 =
    document.getElementById("step1");

const step2 =
    document.getElementById("step2");

const step3 =
    document.getElementById("step3");

const step4 =
    document.getElementById("step4");

const step5 =
    document.getElementById("step5");

const periodSequence =
    document.getElementById("periodSequence");

const periodCalculation =
    document.getElementById("periodCalculation");

const discoveredFactor1 =
    document.getElementById("discoveredFactor1");

const discoveredFactor2 =
    document.getElementById("discoveredFactor2");

const factorizationN =
    document.getElementById("factorizationN");

const attackResult =
    document.getElementById("attackResult");

const threatStatus =
    document.getElementById("threatStatus");


// ------------------------------------------------------------
// VULNERABILITY DETECTION ELEMENTS
// ------------------------------------------------------------

const vulnerabilityN =
    document.getElementById("vulnerabilityN");

const factorizationStatus =
    document.getElementById("factorizationStatus");

const rsaSecurityStatus =
    document.getElementById("rsaSecurityStatus");

const detectionMessage =
    document.getElementById("detectionMessage");

const detectionExplanation =
    document.getElementById("detectionExplanation");


// ------------------------------------------------------------
// INITIAL DISPLAY
// ------------------------------------------------------------

rsaModulusElement.textContent =
    rsaModulus;

quantumNElement.textContent =
    quantumN;

quantumAElement.textContent =
    quantumA;

gcdResultElement.textContent =
    "1";

periodResultElement.textContent =
    "?";

factorPElement.textContent =
    "Unknown";

factorQElement.textContent =
    "Unknown";

discoveredFactor1.textContent =
    "?";

discoveredFactor2.textContent =
    "?";

factorizationN.textContent =
    "?";

attackResult.textContent =
    "Quantum attack has not started.";

threatStatus.textContent =
    "WAITING";

vulnerabilityN.textContent =
    quantumN;

factorizationStatus.textContent =
    "NOT ANALYZED";

rsaSecurityStatus.textContent =
    "SECURE";

detectionMessage.textContent =
    "Waiting for quantum attack analysis.";

detectionExplanation.textContent =
    "RSA security relies on the difficulty of factoring the modulus n into its prime factors.";


// ------------------------------------------------------------
// DISPLAY CIPHERTEXT ACCESS TRIGGER
// ------------------------------------------------------------

if (ciphertextAccessAttempt) {

    detectionMessage.innerHTML =
        "⚠ CIPHERTEXT ACCESS ATTEMPT DETECTED";

    detectionExplanation.innerHTML =
        "The system detected an attempt to access or download the RSA ciphertext. " +
        "The self-healing mechanism has activated the quantum threat analysis " +
        "to evaluate the security of the classical RSA protection.";

    threatStatus.textContent =
        "THREAT DETECTED";

}


// ------------------------------------------------------------
// GREATEST COMMON DIVISOR
// ------------------------------------------------------------

function gcd(a, b) {

    while (b !== 0) {

        const remainder =
            a % b;

        a = b;
        b = remainder;
    }

    return a;
}


// ------------------------------------------------------------
// MODULAR EXPONENTIATION
//
// Calculates:
//
// base^exponent mod modulus
// ------------------------------------------------------------

function modularExponentiation(
    base,
    exponent,
    modulus
) {

    let result = 1;

    base =
        base % modulus;

    while (exponent > 0) {

        if (exponent % 2 === 1) {

            result =
                (result * base) % modulus;
        }

        exponent =
            Math.floor(
                exponent / 2
            );

        base =
            (base * base) % modulus;
    }

    return result;
}


// ------------------------------------------------------------
// START SHOR'S ALGORITHM
// ------------------------------------------------------------

startShorButton.addEventListener(
    "click",
    function () {

        // ----------------------------------------------------
        // RESET DISPLAY
        // ----------------------------------------------------

        factorPElement.textContent =
            "Unknown";

        factorQElement.textContent =
            "Unknown";

        discoveredFactor1.textContent =
            "?";

        discoveredFactor2.textContent =
            "?";

        factorizationN.textContent =
            "?";

        periodResultElement.textContent =
            "?";

        factorizationStatus.textContent =
            "ANALYZING";

        rsaSecurityStatus.textContent =
            "UNDER ANALYSIS";

        detectionMessage.textContent =
            "Analyzing whether the RSA modulus can be factored.";

        detectionExplanation.textContent =
            "The system is checking whether the quantum attack can recover the prime factors of the RSA modulus.";


        // ----------------------------------------------------
        // STEP 1
        // SELECT BASE
        // ----------------------------------------------------

        const a =
            quantumA;

        const N =
            quantumN;

        step1.innerHTML =
            `Select a value <strong>a</strong> such that
             1 &lt; a &lt; N.<br><br>
             Selected value:
             <strong>a = ${a}</strong><br>
             Target:
             <strong>N = ${N}</strong>`;


        // ----------------------------------------------------
        // STEP 2
        // CALCULATE GCD
        // ----------------------------------------------------

        const gcdValue =
            gcd(a, N);

        gcdResultElement.textContent =
            gcdValue;

        step2.innerHTML =
            `Calculate gcd(a, N).<br><br>
             gcd(${a}, ${N}) =
             <strong>${gcdValue}</strong><br><br>
             Since gcd(${a}, ${N}) = 1,
             the quantum period-finding stage is required.`;


        // ----------------------------------------------------
        // STEP 3
        // PERIOD FINDING
        // ----------------------------------------------------

        const r =
            knownPeriod;

        periodResultElement.textContent =
            r;

        const powerAtPeriod =
            modularExponentiation(
                a,
                r,
                N
            );

        const powerAtHalfPeriod =
            modularExponentiation(
                a,
                r / 2,
                N
            );

        step3.innerHTML =
            `Find the smallest positive integer
             <strong>r</strong> such that
             a<sup>r</sup> mod N = 1.<br><br>

             ${a}<sup>${r}</sup> mod ${N}
             = <strong>${powerAtPeriod}</strong><br><br>

             Therefore, the period is:
             <strong>r = ${r}</strong>`;


        // ----------------------------------------------------
        // DISPLAY PERIOD SEQUENCE
        // ----------------------------------------------------

        const sequenceValues = [];

        for (
            let x = 0;
            x <= 8;
            x++
        ) {

            sequenceValues.push(
                `${a}<sup>${x}</sup> mod ${N}
                 = ${modularExponentiation(a, x, N)}`
            );
        }

        periodSequence.innerHTML =
            sequenceValues.join("<br>") +
            `<br><br>
             ...<br><br>
             ${a}<sup>${r}</sup> mod ${N}
             = ${powerAtPeriod}`;


        // ----------------------------------------------------
        // DISPLAY PERIOD CALCULATION
        // ----------------------------------------------------

        periodCalculation.innerHTML =
            `a<sup>r</sup> mod N = 1<br><br>

             ${a}<sup>${r}</sup> mod ${N}
             = ${powerAtPeriod}<br><br>

             r = <strong>${r}</strong><br><br>

             r is even, so factor extraction
             can continue using r / 2.<br><br>

             a<sup>r/2</sup> mod N
             = ${a}<sup>${r / 2}</sup> mod ${N}
             = <strong>${powerAtHalfPeriod}</strong>`;


        // ----------------------------------------------------
        // STEP 4
        // CALCULATE FACTORS
        // ----------------------------------------------------

        const factor1 =
            gcd(
                powerAtHalfPeriod - 1,
                N
            );

        const factor2 =
            gcd(
                powerAtHalfPeriod + 1,
                N
            );


        step4.innerHTML =
            `Use the period to calculate candidate factors.<br><br>

             Factor 1:<br>
             gcd(a<sup>r/2</sup> − 1, N)<br>
             = gcd(${powerAtHalfPeriod} − 1, ${N})<br>
             = gcd(${powerAtHalfPeriod - 1}, ${N})<br>
             = <strong>${factor1}</strong><br><br>

             Factor 2:<br>
             gcd(a<sup>r/2</sup> + 1, N)<br>
             = gcd(${powerAtHalfPeriod} + 1, ${N})<br>
             = gcd(${powerAtHalfPeriod + 1}, ${N})<br>
             = <strong>${factor2}</strong>`;


        // ----------------------------------------------------
        // STEP 5
        // FACTORIZATION RESULT
        // ----------------------------------------------------

        discoveredFactor1.textContent =
            factor1;

        discoveredFactor2.textContent =
            factor2;

        factorizationN.textContent =
            factor1 * factor2;

        factorPElement.textContent =
            factor1;

        factorQElement.textContent =
            factor2;

        step5.innerHTML =
            `Shor's Algorithm successfully recovered
             the prime factors of the RSA modulus.<br><br>

             <strong>${N} = ${factor1} × ${factor2}</strong><br><br>

             The RSA modulus has been factored without
             directly providing the original prime factors.`;


        // ----------------------------------------------------
        // ATTACK RESULT
        // ----------------------------------------------------

        attackResult.innerHTML =
            `✓ QUANTUM FACTORIZATION SUCCESSFUL<br><br>
             RSA modulus ${N} was factored as
             <strong>${factor1} × ${factor2}</strong>.<br><br>
             This demonstrates the fundamental quantum
             threat to classical RSA.`;


        // ----------------------------------------------------
        // VULNERABILITY DETECTION
        // ----------------------------------------------------

        factorizationStatus.textContent =
            "FACTORS RECOVERED";

        rsaSecurityStatus.textContent =
            "VULNERABLE";

        detectionMessage.innerHTML =
            `⚠ RSA VULNERABILITY DETECTED`;

        detectionExplanation.innerHTML =
            `The quantum simulation successfully recovered
             the prime factors of RSA modulus
             <strong>${N}</strong>.<br><br>

             Since:
             <strong>${N} = ${factor1} × ${factor2}</strong>,
             the factorization barrier protecting this
             classical RSA demonstration has been defeated.<br><br>

             <strong>Self-healing action is now required.</strong>`;


        // ----------------------------------------------------
        // THREAT STATUS
        // ----------------------------------------------------

        threatStatus.textContent =
            "RSA VULNERABLE";


        // ----------------------------------------------------
        // SAVE QUANTUM ATTACK STATE
        // ----------------------------------------------------

        sessionStorage.setItem(
            "quantumAttackDetected",
            "true"
        );

        sessionStorage.setItem(
            "rsaVulnerable",
            "true"
        );

        sessionStorage.setItem(
            "rsaFactor1",
            factor1
        );

        sessionStorage.setItem(
            "rsaFactor2",
            factor2
        );


        // ----------------------------------------------------
        // DISABLE BUTTON AFTER SUCCESS
        // ----------------------------------------------------

        startShorButton.disabled =
            true;


        // ----------------------------------------------------
        // SHOW RSA CIPHERTEXT ACCESS AFTER SHOR
        //
        // Shor's Algorithm does NOT automatically move to PQC.
        // The user first sees the recovered RSA factors.
        // Ciphertext access then triggers self-healing.
        // ----------------------------------------------------

        setTimeout(function () {

            let ciphertextPanel =
                document.getElementById("rsaCiphertextAccessPanel");

            if (!ciphertextPanel) {

                ciphertextPanel =
                    document.createElement("div");

                ciphertextPanel.id =
                    "rsaCiphertextAccessPanel";

                ciphertextPanel.style.marginTop =
                    "25px";

                ciphertextPanel.style.padding =
                    "20px";

                ciphertextPanel.style.background =
                    "#171d2d";

                ciphertextPanel.style.border =
                    "1px solid #8b3d3d";

                ciphertextPanel.style.borderLeft =
                    "4px solid #ff5252";

                ciphertextPanel.style.borderRadius =
                    "10px";

                const originalMessage =
                    sessionStorage.getItem("userMessage") || "";

                const rsaE =
                    17;

                const rsaN =
                    3233;

                const ciphertextValues =
                    [];

                for (
                    let i = 0;
                    i < originalMessage.length;
                    i++
                ) {

                    const messageNumber =
                        originalMessage.charCodeAt(i);

                    ciphertextValues.push(
                        modularExponentiation(
                            messageNumber,
                            rsaE,
                            rsaN
                        )
                    );
                }

                ciphertextPanel.innerHTML =
                    `<div style="color:#ff7b7b;font-size:15px;font-weight:bold;margin-bottom:10px;">
                        RSA CIPHERTEXT AFTER QUANTUM ATTACK
                    </div>

                    <p style="color:#aebbd4;line-height:1.6;margin-bottom:14px;">
                        Shor's Algorithm has successfully factored the RSA modulus.
                        The RSA ciphertext is now exposed as the next security event.
                    </p>

                    <div style="padding:14px;background:#0d1525;border-radius:8px;color:#b8c4dd;font-family:monospace;word-break:break-word;margin-bottom:15px;">
                        Ciphertext:<br><br>
                        <strong>${ciphertextValues.join(" ") || "No ciphertext available"}</strong>
                    </div>

                    <button
                        id="accessRsaCiphertextButton"
                        style="width:100%;"
                    >
                        ACCESS RSA CIPHERTEXT — TRIGGER SELF-HEALING
                    </button>

                    <div
                        id="ciphertextSelfHealingStatus"
                        style="margin-top:12px;color:#91a6ff;font-size:13px;font-weight:bold;"
                    >
                        Waiting for ciphertext access attempt...
                    </div>`;

                const attackResultContainer =
                    attackResult.parentElement;

                if (attackResultContainer) {
                    attackResultContainer.appendChild(
                        ciphertextPanel
                    );
                } else {
                    document.body.appendChild(
                        ciphertextPanel
                    );
                }

                const accessButton =
                    document.getElementById(
                        "accessRsaCiphertextButton"
                    );

                const selfHealingStatus =
                    document.getElementById(
                        "ciphertextSelfHealingStatus"
                    );

                if (accessButton) {

                    accessButton.addEventListener(
                        "click",
                        async function () {

                            sessionStorage.setItem(
                                "ciphertextAccessAttempt",
                                "true"
                            );

                            sessionStorage.setItem(
                                "quantumAttackDetected",
                                "true"
                            );

                            sessionStorage.setItem(
                                "rsaVulnerable",
                                "true"
                            );

                            if (selfHealingStatus) {

                                selfHealingStatus.textContent =
                                    "⚠ CIPHERTEXT ACCESS ATTEMPT DETECTED — SELF-HEALING ACTIVATED";
                            }

                            accessButton.disabled =
                                true;

                            accessButton.textContent =
                                "VALIDATING CONTROLLED TEST";

                            threatStatus.textContent =
                                "SELF-HEALING ACTIVATED";

                            detectionMessage.innerHTML =
                                "⚠ CIPHERTEXT ACCESS ATTEMPT DETECTED";

                            const attackMode =
                                sessionStorage.getItem("vaultAttackMode") || "standalone";

                            if (attackMode === "standalone") {
                                detectionExplanation.textContent =
                                    "The original educational flow is continuing to the separate PQC simulation page. No vault state was changed because this session did not start from the file vault.";
                                setTimeout(function () {
                                    window.location.href = "pqc.html";
                                }, 900);
                                return;
                            }

                            try {
                                const endpoint = attackMode === "repeat"
                                    ? "/api/vault/repeat-attack"
                                    : "/api/vault/threat";
                                const response = await fetch(endpoint, {
                                    method: "POST",
                                    headers: {
                                        "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8"
                                    },
                                    body: new URLSearchParams({
                                        modulus: String(N),
                                        factor1: String(factor1),
                                        factor2: String(factor2),
                                        period: String(r),
                                        sessionId: sessionStorage.getItem("vaultAttackSession") || ""
                                    })
                                });
                                const result = await response.json();
                                if (!response.ok) {
                                    throw new Error(result.error || "The vault rejected the test evidence.");
                                }
                                if (attackMode === "repeat") {
                                    detectionMessage.textContent =
                                        "AUTHORIZED REPEAT ATTACK LOGGED — REVIEW THE REVOCATION EVIDENCE";
                                    detectionExplanation.textContent = result.reason;
                                    selfHealingStatus.textContent = result.reason;
                                    threatStatus.textContent = result.oldRsaTestSessionInvalidated && result.oldPqcKeyVersionRevoked
                                        ? "OLD TEST SESSION + PQC VERSION REVOKED"
                                        : "TEST FACTORIZATION ONLY";
                                } else {
                                    detectionMessage.textContent =
                                        "TOY RSA EVIDENCE VALIDATED — VAULT MIGRATION COMPLETED";
                                    detectionExplanation.textContent = result.message;
                                    selfHealingStatus.textContent = result.message;
                                    threatStatus.textContent = result.state;
                                }
                                setTimeout(function () {
                                    window.location.href = attackMode === "repeat"
                                        ? "threat.html?repeat=1"
                                        : "threat.html?healed=1";
                                }, 900);
                            } catch (error) {
                                accessButton.disabled = false;
                                accessButton.textContent = "RETRY CONTROLLED VAULT EVENT";
                                detectionMessage.textContent = "VAULT THREAT EVENT FAILED";
                                detectionExplanation.textContent = error.message;
                                selfHealingStatus.textContent = error.message;
                            }
                        }
                    );
                }
            }

        }, 2000);

    }
);