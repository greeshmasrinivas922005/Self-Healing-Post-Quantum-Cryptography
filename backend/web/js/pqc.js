// ============================================================
// SELF-HEALING POST-QUANTUM CRYPTOGRAPHY
// PQC RECOVERY SIMULATION
// ============================================================


// ------------------------------------------------------------
// GET ORIGINAL MESSAGE
// ------------------------------------------------------------

const originalMessage =
    sessionStorage.getItem("userMessage");


// ------------------------------------------------------------
// GET PREVIOUS SECURITY STATE
// ------------------------------------------------------------

const quantumAttackDetected =
    sessionStorage.getItem("quantumAttackDetected");

const rsaVulnerable =
    sessionStorage.getItem("rsaVulnerable");


// ------------------------------------------------------------
// DOM ELEMENTS
// ------------------------------------------------------------

const originalMessageElement =
    document.getElementById("originalMessage");

const kemStatus =
    document.getElementById("kemStatus");

const dsaStatus =
    document.getElementById("dsaStatus");

const kemKeyStatus =
    document.getElementById("kemKeyStatus");

const encapsulationStatus =
    document.getElementById("encapsulationStatus");

const sharedSecret =
    document.getElementById("sharedSecret");

const kemButton =
    document.getElementById("kemButton");

const kemMessage =
    document.getElementById("kemMessage");

const kemCalculation =
    document.getElementById("kemCalculation");

const encryptionInput =
    document.getElementById("encryptionInput");

const protectedData =
    document.getElementById("protectedData");

const encryptPqcButton =
    document.getElementById("encryptPqcButton");

const encryptionStatus =
    document.getElementById("encryptionStatus");

const decryptionInput =
    document.getElementById("decryptionInput");

const pqcRecoveredMessage =
    document.getElementById("pqcRecoveredMessage");

const decryptPqcButton =
    document.getElementById("decryptPqcButton");

const decryptionStatus =
    document.getElementById("decryptionStatus");

const signatureStatus =
    document.getElementById("signatureStatus");

const integrityStatus =
    document.getElementById("integrityStatus");

const signatureButton =
    document.getElementById("signatureButton");

const signatureMessage =
    document.getElementById("signatureMessage");

const verifyOriginal =
    document.getElementById("verifyOriginal");

const verifyRecovered =
    document.getElementById("verifyRecovered");

const finalResult =
    document.getElementById("finalResult");

const currentProtection =
    document.getElementById("currentProtection");

const systemStatus =
    document.getElementById("systemStatus");


// ------------------------------------------------------------
// SHOR VS ML-KEM DOM ELEMENTS
// ------------------------------------------------------------

const shorComparisonResult =
    document.getElementById("shorComparisonResult");


// ------------------------------------------------------------
// PQC VARIABLES
// ------------------------------------------------------------

let kemKeyMaterial = null;

let sharedSecretValue = null;

let protectedMessage = null;

let recoveredMessageValue = null;

let signatureGenerated = false;

let integrityVerified = false;


// ------------------------------------------------------------
// DISPLAY ORIGINAL MESSAGE
// ------------------------------------------------------------

if (originalMessage) {

    originalMessageElement.textContent =
        originalMessage;

    encryptionInput.textContent =
        originalMessage;

    verifyOriginal.textContent =
        originalMessage;

} else {

    originalMessageElement.textContent =
        "No message available.";

    encryptionInput.textContent =
        "No message available.";

    verifyOriginal.textContent =
        "No message available.";
}


// ------------------------------------------------------------
// INITIAL SYSTEM STATE
// ------------------------------------------------------------

kemStatus.textContent =
    "READY";

dsaStatus.textContent =
    "READY";

currentProtection.textContent =
    "PQC";

systemStatus.textContent =
    "RECOVERING";


// ------------------------------------------------------------
// VERIFY PREVIOUS QUANTUM ATTACK
// ------------------------------------------------------------

if (
    quantumAttackDetected === "true" &&
    rsaVulnerable === "true"
) {

    kemMessage.textContent =
        "Quantum attack detected. Self-healing recovery has been initiated.";

} else {

    kemMessage.textContent =
        "Post-quantum recovery simulation is ready.";
}


// ------------------------------------------------------------
// GENERATE SIMULATED PQC KEY MATERIAL
//
// This is an educational browser simulation of the
// ML-KEM-768 recovery stage.
// ------------------------------------------------------------

kemButton.addEventListener(
    "click",
    function () {

        // ----------------------------------------------------
        // CREATE RANDOM KEY MATERIAL
        // ----------------------------------------------------

        const randomValues =
            new Uint8Array(16);

        crypto.getRandomValues(
            randomValues
        );


        kemKeyMaterial =
            Array.from(
                randomValues
            );


        // ----------------------------------------------------
        // CREATE SHARED SECRET
        // ----------------------------------------------------

        const secretValues =
            new Uint8Array(16);

        crypto.getRandomValues(
            secretValues
        );


        sharedSecretValue =
            Array.from(
                secretValues
            );


        // ----------------------------------------------------
        // DISPLAY ML-KEM-768 CALCULATION
        // ----------------------------------------------------

        if (kemCalculation) {

            kemCalculation.innerHTML =
                `Key Material Generated: [${kemKeyMaterial.join(", ")}]<br><br>
                 Encapsulation Input: Random 128-bit key material<br>
                 Shared Secret Generated: [${sharedSecretValue.join(", ")}]<br><br>
                 Process: Key Generation → Encapsulation → Shared Secret Established<br>
                 Result: New shared secret ready for PQC data protection.`;
        }


        // ----------------------------------------------------
        // UPDATE KEM STATUS
        // ----------------------------------------------------

        kemStatus.textContent =
            "ACTIVE";

        kemKeyStatus.textContent =
            "PQC key material generated";

        encapsulationStatus.textContent =
            "Encapsulation successful";

        sharedSecret.textContent =
            "SHARED SECRET READY";


        kemMessage.innerHTML =
            `✓ Self-healing recovery activated.<br><br>
             ML-KEM-768 key-material simulation completed.<br>
             A new shared secret has been established.<br><br>
             Classical RSA protection is no longer used
             for the recovered data.`;


        // ----------------------------------------------------
        // ENABLE PQC ENCRYPTION
        // ----------------------------------------------------

        encryptPqcButton.disabled =
            false;


        // ----------------------------------------------------
        // UPDATE SYSTEM STATUS
        // ----------------------------------------------------

        systemStatus.textContent =
            "PQC KEY READY";
    }
);


// ------------------------------------------------------------
// SIMPLE XOR ENCRYPTION FOR DEMONSTRATION
//
// The actual project UI represents the PQC protection layer.
// This browser simulation uses the generated shared secret
// to demonstrate protected-data transformation.
// ------------------------------------------------------------

function xorEncrypt(
    text,
    key
) {

    const result = [];

    for (
        let i = 0;
        i < text.length;
        i++
    ) {

        const textValue =
            text.charCodeAt(i);

        const keyValue =
            key[i % key.length];

        result.push(
            textValue ^ keyValue
        );
    }

    return result;
}


// ------------------------------------------------------------
// XOR DECRYPTION
// ------------------------------------------------------------

function xorDecrypt(
    data,
    key
) {

    let text = "";

    for (
        let i = 0;
        i < data.length;
        i++
    ) {

        const decryptedValue =
            data[i] ^
            key[i % key.length];

        text +=
            String.fromCharCode(
                decryptedValue
            );
    }

    return text;
}


// ------------------------------------------------------------
// CONVERT ARRAY TO DISPLAY FORMAT
// ------------------------------------------------------------

function displayProtectedData(
    data
) {

    return data.join(" ");
}


// ------------------------------------------------------------
// PQC ENCRYPTION
// ------------------------------------------------------------

encryptPqcButton.addEventListener(
    "click",
    function () {

        // ----------------------------------------------------
        // CHECK KEY MATERIAL
        // ----------------------------------------------------

        if (
            !sharedSecretValue ||
            sharedSecretValue.length === 0
        ) {

            alert(
                "Please generate PQC key material first."
            );

            return;
        }


        // ----------------------------------------------------
        // CHECK MESSAGE
        // ----------------------------------------------------

        if (!originalMessage) {

            alert(
                "No message is available for encryption."
            );

            return;
        }


        // ----------------------------------------------------
        // ENCRYPT MESSAGE
        // ----------------------------------------------------

        protectedMessage =
            xorEncrypt(
                originalMessage,
                sharedSecretValue
            );


        // ----------------------------------------------------
        // DISPLAY PROTECTED DATA
        // ----------------------------------------------------

        const protectedDisplay =
            displayProtectedData(
                protectedMessage
            );

        protectedData.textContent =
            protectedDisplay;

        decryptionInput.textContent =
            protectedDisplay;


        // ----------------------------------------------------
        // UPDATE STATUS
        // ----------------------------------------------------

        encryptionStatus.textContent =
            "Data encrypted successfully using PQC shared-secret protection.";

        kemStatus.textContent =
            "ACTIVE";

        systemStatus.textContent =
            "PQC DATA ENCRYPTED";


        // ----------------------------------------------------
        // ENABLE DECRYPTION
        // ----------------------------------------------------

        decryptPqcButton.disabled =
            false;


        // ----------------------------------------------------
        // ENABLE SIGNATURE
        // ----------------------------------------------------

        signatureButton.disabled =
            false;


        // ----------------------------------------------------
        // RESET FINAL STATES
        // ----------------------------------------------------

        signatureStatus.textContent =
            "NOT GENERATED";

        integrityStatus.textContent =
            "WAITING";

        signatureGenerated =
            false;

        integrityVerified =
            false;

        finalResult.textContent =
            "Waiting for complete post-quantum verification.";
    }
);


// ------------------------------------------------------------
// PQC DECRYPTION
// ------------------------------------------------------------

decryptPqcButton.addEventListener(
    "click",
    function () {

        // ----------------------------------------------------
        // CHECK PROTECTED DATA
        // ----------------------------------------------------

        if (
            !protectedMessage ||
            protectedMessage.length === 0
        ) {

            alert(
                "Please encrypt the data first."
            );

            return;
        }


        // ----------------------------------------------------
        // DECRYPT DATA
        // ----------------------------------------------------

        recoveredMessageValue =
            xorDecrypt(
                protectedMessage,
                sharedSecretValue
            );


        // ----------------------------------------------------
        // DISPLAY RECOVERED MESSAGE
        // ----------------------------------------------------

        pqcRecoveredMessage.textContent =
            recoveredMessageValue;

        verifyRecovered.textContent =
            recoveredMessageValue;


        // ----------------------------------------------------
        // UPDATE STATUS
        // ----------------------------------------------------

        decryptionStatus.textContent =
            "Protected data decrypted successfully using the PQC shared secret.";

        systemStatus.textContent =
            "PQC DATA DECRYPTED";


        // ----------------------------------------------------
        // CHECK MESSAGE RECOVERY
        // ----------------------------------------------------

        if (
            recoveredMessageValue ===
            originalMessage
        ) {

            decryptionStatus.textContent =
                "✓ Decryption successful — original message recovered.";

        } else {

            decryptionStatus.textContent =
                "✗ Decryption failed — message mismatch.";
        }
    }
);


// ------------------------------------------------------------
// ML-DSA DIGITAL SIGNATURE SIMULATION
// ------------------------------------------------------------

signatureButton.addEventListener(
    "click",
    async function () {

        // ----------------------------------------------------
        // CHECK RECOVERED MESSAGE
        // ----------------------------------------------------

        if (
            !recoveredMessageValue
        ) {

            alert(
                "Please decrypt the protected data first."
            );

            return;
        }


        // ----------------------------------------------------
        // CREATE MESSAGE HASH
        //
        // SHA-256 is used here to create an educational
        // integrity fingerprint for the ML-DSA stage.
        // ----------------------------------------------------

        const encoder =
            new TextEncoder();

        const data =
            encoder.encode(
                recoveredMessageValue
            );

        const hashBuffer =
            await crypto.subtle.digest(
                "SHA-256",
                data
            );

        const hashArray =
            Array.from(
                new Uint8Array(
                    hashBuffer
                )
            );

        const signature =
            hashArray
                .map(
                    value =>
                        value
                            .toString(16)
                            .padStart(2, "0")
                )
                .join("");


        // ----------------------------------------------------
        // SIGNATURE GENERATED
        // ----------------------------------------------------

        signatureGenerated =
            true;

        signatureStatus.textContent =
            "GENERATED";

        integrityStatus.textContent =
            "VERIFYING";


        signatureMessage.innerHTML =
            `ML-DSA signature simulation generated.<br><br>
             Message integrity fingerprint created successfully.`;


        // ----------------------------------------------------
        // VERIFY INTEGRITY
        // ----------------------------------------------------

        const verificationData =
            encoder.encode(
                originalMessage
            );

        const verificationHashBuffer =
            await crypto.subtle.digest(
                "SHA-256",
                verificationData
            );

        const verificationHashArray =
            Array.from(
                new Uint8Array(
                    verificationHashBuffer
                )
            );

        const verificationSignature =
            verificationHashArray
                .map(
                    value =>
                        value
                            .toString(16)
                            .padStart(2, "0")
                )
                .join("");


        if (
            signature ===
            verificationSignature
        ) {

            integrityVerified =
                true;

            integrityStatus.textContent =
                "VERIFIED";

            signatureStatus.textContent =
                "VALID";

            signatureMessage.innerHTML =
                `✓ ML-DSA signature verification successful.<br><br>
                 Message authenticity and integrity confirmed.`;

            systemStatus.textContent =
                "PQC VERIFIED";

        } else {

            integrityVerified =
                false;

            integrityStatus.textContent =
                "FAILED";

            signatureStatus.textContent =
                "INVALID";

            signatureMessage.textContent =
                "✗ ML-DSA verification failed.";

            systemStatus.textContent =
                "VERIFICATION FAILED";
        }


        // ----------------------------------------------------
        // FINAL SECURITY VERIFICATION
        // ----------------------------------------------------

        if (
            recoveredMessageValue ===
            originalMessage &&
            signatureGenerated &&
            integrityVerified
        ) {

            finalResult.innerHTML =
                `✓ FINAL SECURITY VERIFICATION SUCCESSFUL<br><br>
                 Original message matches recovered message.<br>
                 PQC protection is active.<br>
                 Message integrity has been verified.<br><br>
                 <strong>SELF-HEALING RECOVERY COMPLETED.</strong>`;

            systemStatus.textContent =
                "SELF-HEALED";


            // ------------------------------------------------
            // SAVE FINAL SYSTEM STATE
            // ------------------------------------------------

            sessionStorage.setItem(
                "pqcActive",
                "true"
            );

            sessionStorage.setItem(
                "selfHealingCompleted",
                "true"
            );

            sessionStorage.setItem(
                "pqcVerified",
                "true"
            );

        } else {

            finalResult.textContent =
                "Post-quantum verification is incomplete.";
        }
    }
);


// ============================================================
// SHOR'S ALGORITHM VS ML-KEM-768 DEMONSTRATION
// ============================================================
//
// This is an educational simulation.
// It demonstrates that the RSA factorization attack
// simulated earlier does not directly apply to ML-KEM.
//
// It is NOT an actual quantum computation.
// ============================================================

function runShorVsMlKemDemo() {

    if (!shorComparisonResult) {
        return;
    }


    // --------------------------------------------------------
    // INITIAL STATE
    // --------------------------------------------------------

    shorComparisonResult.innerHTML =
        `Quantum Attack Target: RSA<br><br>
         Shor's Algorithm → Integer Factorization<br>
         RSA modulus → Prime Factors → RSA Vulnerable<br><br>
         Analyzing ML-KEM-768 protection...`;


    systemStatus.textContent =
        "QUANTUM ATTACK ANALYSIS";


    // --------------------------------------------------------
    // STEP 2
    // --------------------------------------------------------

    setTimeout(function () {

        shorComparisonResult.innerHTML =
            `RSA:<br>
             Shor's algorithm → Factor RSA modulus → RSA broken
             <br><br>
             ML-KEM-768:<br>
             Shor's RSA factorization method → No RSA modulus
             to factor
             <br><br>
             Continuing post-quantum security analysis...`;

    }, 1200);


    // --------------------------------------------------------
    // FINAL RESULT
    // --------------------------------------------------------

    setTimeout(function () {

        shorComparisonResult.innerHTML =
            `<strong>✓ SHOR'S RSA FACTORIZATION ATTACK DOES NOT BREAK ML-KEM-768</strong>
             <br><br>
             RSA is vulnerable because its security depends on
             integer factorization.
             <br><br>
             ML-KEM-768 uses a lattice-based construction,
             so the RSA factorization attack demonstrated by
             Shor's algorithm is not applicable.
             <br><br>
             <strong>RESULT: POST-QUANTUM PROTECTION REMAINS ACTIVE.</strong>`;

        systemStatus.textContent =
            "PQC RESISTANT TO THIS SHOR ATTACK";

        sessionStorage.setItem(
            "shorVsMlKemCompleted",
            "true"
        );

    }, 2500);
}


// ------------------------------------------------------------
// SHOR COMPARISON BUTTON
// ------------------------------------------------------------

const runShorComparison =
    document.getElementById("runShorComparison");


if (runShorComparison) {

    runShorComparison.addEventListener(
        "click",
        runShorVsMlKemDemo
    );
}