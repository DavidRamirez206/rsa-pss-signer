package co.edu.icesi.signer.timestamp;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;

/** Asks a {@link TimeServer} to stamp a {@code .sig}, sending only its hash. */
public final class TimeClient {

    private static final Duration TIMEOUT = Duration.ofSeconds(10);

    private TimeClient() {
    }

    /**
     * Requests a time stamp. The token's signature is not checked here: verifying with the
     * authority's public key does that, as for any token.
     *
     * @param authority the server's base address, such as {@code http://127.0.0.1:8318}
     * @throws IOException if the server cannot be reached or answers with something else
     */
    public static TimeToken request(URI authority, byte[] sigFile) throws IOException {
        String scheme = authority.getScheme();
        if (!"http".equals(scheme) && !"https".equals(scheme)) {
            throw new IOException("The time authority's address must start with http:// or https://");
        }
        String sigHash = TimeAuthority.hash(sigFile);
        HttpRequest request = HttpRequest.newBuilder(authority.resolve(TimeServer.PATH))
                .timeout(TIMEOUT)
                .header("Content-Type", "text/plain")
                .POST(HttpRequest.BodyPublishers.ofString(sigHash, StandardCharsets.US_ASCII))
                .build();
        HttpResponse<InputStream> response;
        try {
            response = HttpClient.newBuilder().connectTimeout(TIMEOUT).build()
                    .send(request, HttpResponse.BodyHandlers.ofInputStream());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("Interrupted while waiting for the time authority", e);
        }
        byte[] body;
        try (InputStream in = response.body()) {
            body = in.readNBytes((int) TimeToken.MAX_FILE_SIZE + 1);
        }
        if (body.length > TimeToken.MAX_FILE_SIZE) {
            throw new IOException("The time authority's answer is too large");
        }
        if (response.statusCode() != 200) {
            throw new IOException("The time authority answered " + response.statusCode() + ": "
                    + new String(body, StandardCharsets.UTF_8).strip());
        }
        TimeToken token = TimeToken.parse(body);
        if (!token.sigHash().equals(sigHash)) {
            throw new IOException("The time authority stamped something else");
        }
        return token;
    }
}
