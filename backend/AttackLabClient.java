import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

public final class AttackLabClient {
    private static final String CHALLENGE_PATH = "/api/lab/challenge?purpose=";
    private static final String INITIAL_SUBMIT_PATH = "/api/lab/submit/initial";
    private static final String REPEAT_SUBMIT_PATH = "/api/lab/submit/repeat";

    private AttackLabClient() { }

    public static void main(String[] args) throws Exception {
        String purpose = args.length == 0 ? "initial" : args[0];
        if (!purpose.equals("initial") && !purpose.equals("repeat")) {
            throw new IllegalArgumentException("Usage: java -cp backend AttackLabClient [initial|repeat]");
        }
        String host = required("VAULT_TARGET_HOST");
        if (host.contains("://") || host.contains("/") || host.contains("\\") || host.contains(" ")) {
            throw new IllegalArgumentException("VAULT_TARGET_HOST must be a host name or IP only, without a URL or path.");
        }
        int port = Integer.parseInt(required("VAULT_TARGET_PORT"));
        if (port < 1 || port > 65535) throw new IllegalArgumentException("VAULT_TARGET_PORT must be between 1 and 65535.");
        String token = required("VAULT_LAB_TOKEN");
        URI base = new URI("https", null, host, port, null, null, null);
        HttpClient client = HttpClient.newBuilder()
                .sslContext(createClientSslContext())
                .connectTimeout(Duration.ofSeconds(8))
                .followRedirects(HttpClient.Redirect.NEVER)
                .build();

        System.out.println("VaultIQ authorized RSA test client");
        System.out.println("Configured target: " + base.getHost() + ":" + base.getPort());
        System.out.println("Purpose: " + purpose + " controlled demonstration");
        System.out.println("Connecting over HTTPS with the configured client certificate...");

        HttpResponse<String> challengeResponse = send(client, base.resolve(CHALLENGE_PATH + purpose), token, null);
        requireSuccess(challengeResponse, "Challenge request");
        String challenge = challengeResponse.body();
        String targetId = jsonString(challenge, "targetId");
        int modulus = jsonInt(challenge, "modulus");
        int publicExponent = jsonInt(challenge, "publicExponent");
        String sessionId = jsonString(challenge, "sessionId");
        String expectedHash = jsonString(challenge, "recoveredSha256");
        int[] ciphertext = Arrays.stream(jsonString(challenge, "ciphertextNumbers").split(","))
                .mapToInt(Integer::parseInt).toArray();
        if (!targetId.equals("PROJECT_RSA_3233") || modulus != 3233 || publicExponent != 17) {
            throw new SecurityException("Server challenge is not the fixed project-owned test target.");
        }

        System.out.println("HTTPS connection established; server challenge: " + targetId);
        System.out.println("Test public parameters: N=" + modulus + ", e=" + publicExponent);
        System.out.println("Test ciphertext values: " + ciphertext.length);
        int period = findClassicalPeriod(3, modulus);
        int halfPower = modularExponentiation(3, period / 2, modulus);
        int factor1 = gcd(halfPower - 1, modulus);
        int factor2 = gcd(halfPower + 1, modulus);
        int phi = (factor1 - 1) * (factor2 - 1);
        int privateExponent = modularInverse(publicExponent, phi);
        String recovered = decryptToyText(ciphertext, privateExponent, modulus);
        String recoveredHash = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                .digest(recovered.getBytes(StandardCharsets.UTF_8)));
        if (!MessageDigest.isEqual(expectedHash.getBytes(StandardCharsets.US_ASCII),
                recoveredHash.getBytes(StandardCharsets.US_ASCII))) {
            throw new SecurityException("Recovered test challenge does not match the server's expected digest.");
        }

        System.out.println("Classical educational period finding: r=" + period);
        System.out.println("Recovered test factors: " + factor1 + " × " + factor2);
        System.out.println("Recovered challenge hash matches the server challenge.");
        System.out.println("Submitting verified evidence to the fixed project endpoint...");
        String form = "sessionId=" + enc(sessionId)
                + "&modulus=" + modulus
                + "&factor1=" + factor1
                + "&factor2=" + factor2
                + "&period=" + period
                + "&recoveredSha256=" + enc(recoveredHash);
        String submitPath = purpose.equals("repeat") ? REPEAT_SUBMIT_PATH : INITIAL_SUBMIT_PATH;
        HttpResponse<String> result = send(client, base.resolve(submitPath), token, form);
        requireSuccess(result, "Evidence submission");
        System.out.println("Computer A accepted the lab event:");
        System.out.println(result.body());
        System.out.println("This demonstrates the authorized toy RSA test only; it is not a quantum computation.");
    }

    private static HttpResponse<String> send(HttpClient client, URI uri, String token, String body)
            throws Exception {
        HttpRequest.Builder request = HttpRequest.newBuilder(uri)
                .timeout(Duration.ofSeconds(15))
                .header("Authorization", "Bearer " + token)
                .header("Accept", "application/json");
        if (body == null) {
            request.GET();
        } else {
            request.header("Content-Type", "application/x-www-form-urlencoded;charset=UTF-8")
                    .POST(HttpRequest.BodyPublishers.ofString(body));
        }
        return client.send(request.build(), HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
    }

    private static void requireSuccess(HttpResponse<String> response, String operation) {
        if (response.statusCode() < 200 || response.statusCode() >= 300) {
            throw new IllegalStateException(operation + " rejected by Computer A (HTTP "
                    + response.statusCode() + "): " + response.body());
        }
    }

    private static SSLContext createClientSslContext() throws Exception {
        KeyStore clientKeys = loadStore("VAULT_TLS_CLIENT_KEYSTORE", "VAULT_TLS_CLIENT_KEYSTORE_PASSWORD");
        KeyStore trustedServer = loadStore("VAULT_TLS_TRUSTSTORE", "VAULT_TLS_TRUSTSTORE_PASSWORD");
        KeyManagerFactory keyManagers = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keyManagers.init(clientKeys, required("VAULT_TLS_CLIENT_KEYSTORE_PASSWORD").toCharArray());
        TrustManagerFactory trustManagers = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trustManagers.init(trustedServer);
        SSLContext context = SSLContext.getInstance("TLSv1.3");
        context.init(keyManagers.getKeyManagers(), trustManagers.getTrustManagers(), null);
        return context;
    }

    private static KeyStore loadStore(String pathName, String passwordName) throws Exception {
        char[] password = required(passwordName).toCharArray();
        KeyStore store = KeyStore.getInstance("PKCS12");
        try (var input = Files.newInputStream(Path.of(required(pathName)))) {
            store.load(input, password);
        } finally {
            Arrays.fill(password, '\0');
        }
        return store;
    }

    private static int findClassicalPeriod(int base, int modulus) {
        for (int period = 1; period <= modulus; period++) {
            if (modularExponentiation(base, period, modulus) == 1) return period;
        }
        throw new IllegalStateException("No period found for the fixed toy target.");
    }

    private static int modularExponentiation(int base, int exponent, int modulus) {
        long result = 1;
        long factor = base % modulus;
        while (exponent > 0) {
            if ((exponent & 1) == 1) result = (result * factor) % modulus;
            factor = (factor * factor) % modulus;
            exponent >>>= 1;
        }
        return (int) result;
    }

    private static int gcd(int first, int second) {
        while (second != 0) {
            int remainder = first % second;
            first = second;
            second = remainder;
        }
        return Math.abs(first);
    }

    private static int modularInverse(int value, int modulus) {
        return java.math.BigInteger.valueOf(value)
                .modInverse(java.math.BigInteger.valueOf(modulus)).intValue();
    }

    private static String decryptToyText(int[] ciphertext, int privateExponent, int modulus) {
        StringBuilder plaintext = new StringBuilder();
        for (int value : ciphertext) {
            int character = modularExponentiation(value, privateExponent, modulus);
            if (character < 0 || character > Character.MAX_VALUE) {
                throw new SecurityException("Decrypted test value is outside the supported character range.");
            }
            plaintext.append((char) character);
        }
        return plaintext.toString();
    }

    private static String jsonString(String json, String key) {
        String expression = "\"" + Pattern.quote(key) + "\"\\s*:\\s*\"((?:\\\\.|[^\"\\\\])*)\"";
        Matcher matcher = Pattern.compile(expression).matcher(json);
        if (!matcher.find()) throw new IllegalArgumentException("Server response is missing " + key + ".");
        return matcher.group(1).replace("\\\"", "\"").replace("\\\\", "\\");
    }

    private static int jsonInt(String json, String key) {
        Matcher matcher = Pattern.compile("\"" + Pattern.quote(key) + "\"\\s*:\\s*(-?\\d+)").matcher(json);
        if (!matcher.find()) throw new IllegalArgumentException("Server response is missing " + key + ".");
        return Integer.parseInt(matcher.group(1));
    }

    private static String enc(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    private static String required(String name) {
        String value = System.getenv(name);
        if (value == null || value.isBlank()) throw new IllegalArgumentException("Set " + name + " for the authorized lab client.");
        return value;
    }
}
