// ============================================================
// RSA CRYPTOGRAPHY SIMULATION
// ============================================================

// Get the message sent from the first interface
const originalMessage = sessionStorage.getItem("userMessage");


// ------------------------------------------------------------
// DOM ELEMENTS
// ------------------------------------------------------------

const originalMessageElement =
    document.getElementById("originalMessage");

const encryptionMessage =
    document.getElementById("encryptionMessage");

const messageNumber =
    document.getElementById("messageNumber");

const ciphertext =
    document.getElementById("ciphertext");

const decryptionCiphertext =
    document.getElementById("decryptionCiphertext");

const decryptedNumber =
    document.getElementById("decryptedNumber");

const recoveredMessage =
    document.getElementById("recoveredMessage");

const verifyOriginal =
    document.getElementById("verifyOriginal");

const verifyRecovered =
    document.getElementById("verifyRecovered");

const verificationResult =
    document.getElementById("verificationResult");

const generateKeysButton =
    document.getElementById("generateKeys");

const encryptButton =
    document.getElementById("encryptButton");

const decryptButton =
    document.getElementById("decryptButton");

const keyStatus =
    document.getElementById("keyStatus");

const encryptionStatus =
    document.getElementById("encryptionStatus");

const decryptionStatus =
    document.getElementById("decryptionStatus");

const systemStatus =
    document.getElementById("systemStatus");


// ------------------------------------------------------------
// CIPHERTEXT DOWNLOAD / SELF-HEALING ELEMENTS
// ------------------------------------------------------------

const downloadCipherButton =
    document.getElementById("downloadCipherButton");

const downloadWarning =
    document.getElementById("downloadWarning");


// ------------------------------------------------------------
// RSA CALCULATION ELEMENTS
// ------------------------------------------------------------

const calculationPrimes =
    document.getElementById("calculationPrimes");

const calculationN =
    document.getElementById("calculationN");

const calculationPhi =
    document.getElementById("calculationPhi");

const calculationE =
    document.getElementById("calculationE");

const calculationD =
    document.getElementById("calculationD");

const encryptionCalculation =
    document.getElementById("encryptionCalculation");

const decryptionCalculation =
    document.getElementById("decryptionCalculation");


// ------------------------------------------------------------
// RSA VARIABLES
// ------------------------------------------------------------

let p;
let q;
let n;
let phi;
let e;
let d;

let encryptedData = [];
let decryptedData = [];


// ------------------------------------------------------------
// DISPLAY ORIGINAL MESSAGE
// ------------------------------------------------------------

if (originalMessage) {

    originalMessageElement.textContent =
        originalMessage;

    encryptionMessage.textContent =
        originalMessage;

    verifyOriginal.textContent =
        originalMessage;

} else {

    originalMessageElement.textContent =
        "No message was received.";

    encryptionMessage.textContent =
        "No message was received.";

    verifyOriginal.textContent =
        "No message was received.";
}


// ------------------------------------------------------------
// GREATEST COMMON DIVISOR
// ------------------------------------------------------------

function gcd(a, b) {

    while (b !== 0) {

        const remainder = a % b;

        a = b;
        b = remainder;
    }

    return a;
}


// ------------------------------------------------------------
// MODULAR EXPONENTIATION
//
// Calculates:
// base^exponent mod modulus
// ------------------------------------------------------------

function modularExponentiation(
    base,
    exponent,
    modulus
) {

    let result = 1;

    base = base % modulus;

    while (exponent > 0) {

        if (exponent % 2 === 1) {

            result =
                (result * base) % modulus;
        }

        exponent =
            Math.floor(exponent / 2);

        base =
            (base * base) % modulus;
    }

    return result;
}


// ------------------------------------------------------------
// MODULAR MULTIPLICATIVE INVERSE
//
// Finds d such that:
// (d × e) mod phi = 1
// ------------------------------------------------------------

function modularInverse(e, phi) {

    for (let d = 1; d < phi; d++) {

        if ((e * d) % phi === 1) {

            return d;
        }
    }

    return null;
}


// ------------------------------------------------------------
// RSA KEY GENERATION
// ------------------------------------------------------------

generateKeysButton.addEventListener(
    "click",
    function () {

        // ----------------------------------------------------
        // STEP 1: SELECT PRIME NUMBERS
        // ----------------------------------------------------

        p = 61;
        q = 53;


        // ----------------------------------------------------
        // STEP 2: CALCULATE n
        //
        // n = p × q
        // ----------------------------------------------------

        n = p * q;


        // ----------------------------------------------------
        // STEP 3: CALCULATE φ(n)
        //
        // φ(n) = (p - 1)(q - 1)
        // ----------------------------------------------------

        phi =
            (p - 1) * (q - 1);


        // ----------------------------------------------------
        // STEP 4: SELECT PUBLIC EXPONENT
        // ----------------------------------------------------

        e = 17;


        // ----------------------------------------------------
        // VERIFY e
        // ----------------------------------------------------

        const gcdValue =
            gcd(e, phi);


        // ----------------------------------------------------
        // STEP 5: CALCULATE PRIVATE EXPONENT
        //
        // d × e ≡ 1 (mod φ(n))
        // ----------------------------------------------------

        d =
            modularInverse(e, phi);


        // ----------------------------------------------------
        // DISPLAY RSA PARAMETERS
        // ----------------------------------------------------

        document.getElementById(
            "primeP"
        ).textContent = p;

        document.getElementById(
            "primeQ"
        ).textContent = q;

        document.getElementById(
            "modulusN"
        ).textContent = n;

        document.getElementById(
            "phiN"
        ).textContent = phi;

        document.getElementById(
            "publicE"
        ).textContent = e;

        document.getElementById(
            "privateD"
        ).textContent = d;


        // ----------------------------------------------------
        // DISPLAY PUBLIC KEY
        // ----------------------------------------------------

        document.getElementById(
            "publicKey"
        ).textContent =
            `(${e}, ${n})`;


        // ----------------------------------------------------
        // DISPLAY PRIVATE KEY
        // ----------------------------------------------------

        document.getElementById(
            "privateKey"
        ).textContent =
            `(${d}, ${n})`;


        // ----------------------------------------------------
        // DISPLAY RSA KEY GENERATION CALCULATIONS
        // ----------------------------------------------------

        calculationPrimes.innerHTML =
            `p = ${p} &nbsp;&nbsp;&nbsp; q = ${q}`;

        calculationN.innerHTML =
            `n = p × q<br>
             n = ${p} × ${q}<br>
             n = <strong>${n}</strong>`;

        calculationPhi.innerHTML =
            `φ(n) = (p − 1)(q − 1)<br>
             φ(n) = (${p} − 1)(${q} − 1)<br>
             φ(n) = ${p - 1} × ${q - 1}<br>
             φ(n) = <strong>${phi}</strong>`;

        calculationE.innerHTML =
            `Choose e such that gcd(e, φ(n)) = 1<br>
             gcd(${e}, ${phi}) = <strong>${gcdValue}</strong><br>
             Therefore, e = <strong>${e}</strong> is valid.`;

        calculationD.innerHTML =
            `d × e ≡ 1 (mod φ(n))<br>
             d × ${e} ≡ 1 (mod ${phi})<br>
             d = <strong>${d}</strong><br>
             (${d} × ${e}) mod ${phi} = <strong>${(d * e) % phi}</strong><br><br>
             <strong>Private exponent verification successful.</strong><br>
             Therefore, d = ${d} is the valid private exponent.`;


        // ----------------------------------------------------
        // RESET ENCRYPTION CALCULATION
        // ----------------------------------------------------

        encryptionCalculation.innerHTML =
            `C = M<sup>e</sup> mod n`;


        // ----------------------------------------------------
        // RESET DECRYPTION CALCULATION
        // ----------------------------------------------------

        decryptionCalculation.innerHTML =
            `M = C<sup>d</sup> mod n`;


        // ----------------------------------------------------
        // RESET SELF-HEALING / ATTACK STATE
        // ----------------------------------------------------

        sessionStorage.removeItem("ciphertextAccessAttempt");
        sessionStorage.removeItem("quantumAttackDetected");
        sessionStorage.removeItem("rsaVulnerable");

        if (downloadWarning) {
            downloadWarning.textContent = "";
        }


        // ----------------------------------------------------
        // STATUS
        // ----------------------------------------------------

        keyStatus.textContent =
            "RSA keys generated successfully. Public and private keys are ready.";

        encryptionStatus.textContent =
            "RSA keys are ready. Encryption can now be performed.";

        systemStatus.textContent =
            "KEYS READY";


        // ----------------------------------------------------
        // ENABLE ENCRYPTION
        // ----------------------------------------------------

        encryptButton.disabled = false;


        // ----------------------------------------------------
        // RESET LATER STAGES
        // ----------------------------------------------------

        decryptButton.disabled = true;

        if (downloadCipherButton) {
            downloadCipherButton.disabled = true;
        }

        ciphertext.textContent =
            "—";

        decryptionCiphertext.textContent =
            "—";

        decryptedNumber.textContent =
            "—";

        recoveredMessage.textContent =
            "—";

        verifyRecovered.textContent =
            "—";

        verificationResult.textContent =
            "Waiting for decryption verification.";

        encryptedData = [];

        decryptedData = [];
    }
);


// ------------------------------------------------------------
// TEXT → NUMBERS
// ------------------------------------------------------------

function textToNumbers(text) {

    const numbers = [];

    for (let i = 0; i < text.length; i++) {

        numbers.push(
            text.charCodeAt(i)
        );
    }

    return numbers;
}


// ------------------------------------------------------------
// NUMBERS → TEXT
// ------------------------------------------------------------

function numbersToText(numbers) {

    let text = "";

    for (const number of numbers) {

        text +=
            String.fromCharCode(number);
    }

    return text;
}


// ------------------------------------------------------------
// RSA ENCRYPTION
//
// Formula:
// C = M^e mod n
// ------------------------------------------------------------

encryptButton.addEventListener(
    "click",
    function () {

        // ----------------------------------------------------
        // CHECK KEYS
        // ----------------------------------------------------

        if (!p || !q || !n || !e || !d) {

            alert(
                "Please generate RSA keys first."
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
        // CONVERT MESSAGE TO NUMBERS
        // ----------------------------------------------------

        const numbers =
            textToNumbers(
                originalMessage
            );


        // ----------------------------------------------------
        // RSA ENCRYPTION
        //
        // C = M^e mod n
        // ----------------------------------------------------

        encryptedData =
            numbers.map(
                function (m) {

                    return modularExponentiation(
                        m,
                        e,
                        n
                    );
                }
            );


        // ----------------------------------------------------
        // DISPLAY NUMERICAL REPRESENTATION
        // ----------------------------------------------------

        messageNumber.textContent =
            numbers.join(" ");


        // ----------------------------------------------------
        // DISPLAY CIPHERTEXT
        // ----------------------------------------------------

        ciphertext.textContent =
            encryptedData.join(" ");


        // ----------------------------------------------------
        // COPY CIPHERTEXT TO DECRYPTION
        // ----------------------------------------------------

        decryptionCiphertext.textContent =
            encryptedData.join(" ");


        // ----------------------------------------------------
        // DISPLAY DETAILED ENCRYPTION CALCULATION
        // ----------------------------------------------------

        if (numbers.length > 0) {

            const firstMessageNumber =
                numbers[0];

            const firstCiphertext =
                encryptedData[0];

            const firstCharacter =
                originalMessage.charAt(0);

            encryptionCalculation.innerHTML =
                `Character selected: <strong>${firstCharacter}</strong><br>
                 Numerical value: <strong>${firstMessageNumber}</strong><br>
                 Public Key: <strong>(${e}, ${n})</strong><br><br>
                 C = M<sup>e</sup> mod n<br>
                 C = ${firstMessageNumber}<sup>${e}</sup> mod ${n}<br>
                 C = <strong>${firstCiphertext}</strong>
                 <br><br>
                 Each character is encrypted separately using
                 the RSA public key.`;
        }


        // ----------------------------------------------------
        // STATUS
        // ----------------------------------------------------

        encryptionStatus.textContent =
            "Message encrypted successfully using the RSA public key.";

        systemStatus.textContent =
            "DATA ENCRYPTED";


        // ----------------------------------------------------
        // ENABLE DECRYPTION
        // ----------------------------------------------------

        decryptButton.disabled = false;


        // ----------------------------------------------------
        // ENABLE CIPHERTEXT DOWNLOAD
        // ----------------------------------------------------

        if (downloadCipherButton) {
            downloadCipherButton.disabled = false;
        }


        verificationResult.textContent =
            "Ciphertext is ready for decryption.";
    }
);


// ------------------------------------------------------------
// CIPHERTEXT DOWNLOAD ATTEMPT
// SELF-HEALING TRIGGER
// ------------------------------------------------------------

if (downloadCipherButton) {

    downloadCipherButton.addEventListener(
        "click",
        function () {

            // ------------------------------------------------
            // CHECK WHETHER CIPHERTEXT EXISTS
            // ------------------------------------------------

            if (encryptedData.length === 0) {

                alert(
                    "Please encrypt the message first."
                );

                return;
            }


            // ------------------------------------------------
            // DETECT CIPHERTEXT ACCESS ATTEMPT
            // ------------------------------------------------

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


            // ------------------------------------------------
            // DISPLAY SECURITY WARNING
            // ------------------------------------------------

            if (downloadWarning) {

                downloadWarning.textContent =
                    "⚠ CIPHERTEXT ACCESS ATTEMPT DETECTED — SELF-HEALING ACTIVATED";
            }

            encryptionStatus.textContent =
                "⚠ Suspicious ciphertext access detected. RSA protection is considered vulnerable.";

            systemStatus.textContent =
                "SELF-HEALING ACTIVATED";


            // ------------------------------------------------
            // DISABLE DOWNLOAD
            //
            // The ciphertext is NOT actually downloaded.
            // The attempt itself triggers self-healing.
            // ------------------------------------------------

            downloadCipherButton.disabled = true;


            // ------------------------------------------------
            // MOVE TO QUANTUM ATTACK INTERFACE
            // ------------------------------------------------

            setTimeout(function () {

                window.location.href =
                    "quantum.html";

            }, 1500);
        }
    );
}


// ------------------------------------------------------------
// RSA DECRYPTION
//
// Formula:
// M = C^d mod n
// ------------------------------------------------------------

decryptButton.addEventListener(
    "click",
    function () {

        // ----------------------------------------------------
        // CHECK CIPHERTEXT
        // ----------------------------------------------------

        if (encryptedData.length === 0) {

            alert(
                "Please encrypt the message first."
            );

            return;
        }


        // ----------------------------------------------------
        // RSA DECRYPTION
        //
        // M = C^d mod n
        // ----------------------------------------------------

        decryptedData =
            encryptedData.map(
                function (c) {

                    return modularExponentiation(
                        c,
                        d,
                        n
                    );
                }
            );


        // ----------------------------------------------------
        // DISPLAY DECRYPTED NUMBERS
        // ----------------------------------------------------

        decryptedNumber.textContent =
            decryptedData.join(" ");


        // ----------------------------------------------------
        // CONVERT NUMBERS BACK TO TEXT
        // ----------------------------------------------------

        const recoveredText =
            numbersToText(
                decryptedData
            );


        // ----------------------------------------------------
        // DISPLAY RECOVERED MESSAGE
        // ----------------------------------------------------

        recoveredMessage.textContent =
            recoveredText;

        verifyRecovered.textContent =
            recoveredText;


        // ----------------------------------------------------
        // DISPLAY DETAILED DECRYPTION CALCULATION
        // ----------------------------------------------------

        if (encryptedData.length > 0) {

            const firstCiphertext =
                encryptedData[0];

            const firstDecryptedNumber =
                decryptedData[0];

            const recoveredCharacter =
                String.fromCharCode(
                    firstDecryptedNumber
                );

            decryptionCalculation.innerHTML =
                `Ciphertext selected: <strong>${firstCiphertext}</strong><br>
                 Private Key: <strong>(${d}, ${n})</strong><br><br>
                 M = C<sup>d</sup> mod n<br>
                 M = ${firstCiphertext}<sup>${d}</sup> mod ${n}<br>
                 M = <strong>${firstDecryptedNumber}</strong><br><br>
                 Decrypted character: <strong>${recoveredCharacter}</strong>`;
        }


        // ----------------------------------------------------
        // STATUS
        // ----------------------------------------------------

        decryptionStatus.textContent =
            "Ciphertext decrypted successfully using the RSA private key.";

        systemStatus.textContent =
            "DATA DECRYPTED";


        // ----------------------------------------------------
        // RSA VERIFICATION
        // ----------------------------------------------------

        if (
            recoveredText ===
            originalMessage
        ) {

            verificationResult.textContent =
                "✓ VERIFICATION SUCCESSFUL — Original message matches recovered message.";

            systemStatus.textContent =
                "RSA VERIFIED";


            // ------------------------------------------------
            // SAVE RSA VERIFICATION STATE
            // ------------------------------------------------

            sessionStorage.setItem(
                "rsaVerified",
                "true"
            );


            // ------------------------------------------------
            // MOVE TO QUANTUM ATTACK INTERFACE
            // ------------------------------------------------

            setTimeout(function () {

                window.location.href =
                    "quantum.html";

            }, 1500);

        } else {

            verificationResult.textContent =
                "✗ VERIFICATION FAILED — Original and recovered messages do not match.";

            systemStatus.textContent =
                "VERIFICATION FAILED";
        }
    }
);