package co.edu.icesi.signer.timestamp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import co.edu.icesi.signer.crypto.KeyPairService;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/** T-2.8: the time authority as an HTTP service. */
class TimeServerTest {

    private static final Clock CLOCK = Clock.fixed(Instant.parse("2026-11-08T15:00:00Z"), ZoneOffset.UTC);
    private static final byte[] SIG = "{\"a signature\":1}".getBytes(StandardCharsets.UTF_8);

    private static KeyPair keys;
    private static TimeServer server;
    private static URI base;

    @BeforeAll
    static void start() throws Exception {
        keys = KeyPairService.generate(2048);
        server = TimeServer.start(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0),
                (RSAPrivateCrtKey) keys.getPrivate(), CLOCK);
        base = URI.create("http://127.0.0.1:" + server.port());
    }

    @AfterAll
    static void stop() {
        server.close();
    }

    private static HttpResponse<String> send(HttpRequest.Builder request) throws Exception {
        return HttpClient.newHttpClient().send(request.build(), HttpResponse.BodyHandlers.ofString());
    }

    @Test
    void aRequestedStampVerifiesWithTheAuthorityKey() throws Exception {
        TimeToken token = TimeClient.request(base, SIG);

        assertNull(TimeAuthority.problem(token, SIG, (RSAPublicKey) keys.getPublic()));
        assertEquals("2026-11-08T15:00:00Z", Instant.parse(token.time()).toString());
        assertEquals(TimeAuthority.hash(SIG), token.sigHash());
    }

    @Test
    void theStampIsForTheSignatureSent() throws Exception {
        TimeToken token = TimeClient.request(base, SIG);

        assertEquals("reason.timestamp.other",
                TimeAuthority.problem(token, "other".getBytes(StandardCharsets.UTF_8),
                        (RSAPublicKey) keys.getPublic()).key());
    }

    @Test
    void onlyAHashIsAccepted() throws Exception {
        HttpResponse<String> response = send(HttpRequest.newBuilder(base.resolve(TimeServer.PATH))
                .POST(HttpRequest.BodyPublishers.ofString("not a hash")));

        assertEquals(400, response.statusCode());
    }

    @Test
    void aLargeBodyIsRefused() throws Exception {
        HttpResponse<String> response = send(HttpRequest.newBuilder(base.resolve(TimeServer.PATH))
                .POST(HttpRequest.BodyPublishers.ofString("a".repeat(10_000))));

        assertEquals(413, response.statusCode());
    }

    @Test
    void onlyPostIsAllowed() throws Exception {
        assertEquals(405, send(HttpRequest.newBuilder(base.resolve(TimeServer.PATH)).GET()).statusCode());
        assertEquals(404, send(HttpRequest.newBuilder(base.resolve("/other"))
                .POST(HttpRequest.BodyPublishers.noBody())).statusCode());
    }

    // A key outside the allowlists never stamps anything
    @Test
    void theClientReportsAServerError() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(1024);
        try (TimeServer weak = TimeServer.start(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0),
                (RSAPrivateCrtKey) generator.generateKeyPair().getPrivate(), CLOCK)) {
            IOException e = assertThrows(IOException.class,
                    () -> TimeClient.request(URI.create("http://127.0.0.1:" + weak.port()), SIG));
            assertTrue(e.getMessage().contains("500"), e.getMessage());
        }
    }

    // A real authority signs what it is sent; a stamp of something else is not this signature's
    @Test
    void theClientRejectsAStampOfSomethingElse() throws Exception {
        byte[] other = TimeAuthority.stamp("other".getBytes(StandardCharsets.UTF_8),
                (RSAPrivateCrtKey) keys.getPrivate(), CLOCK).toJson();
        HttpServer fake = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        fake.createContext(TimeServer.PATH, exchange -> {
            exchange.sendResponseHeaders(200, other.length);
            try (exchange) {
                exchange.getResponseBody().write(other);
            }
        });
        fake.start();
        try {
            IOException e = assertThrows(IOException.class,
                    () -> TimeClient.request(URI.create("http://127.0.0.1:" + fake.getAddress().getPort()), SIG));
            assertTrue(e.getMessage().contains("stamped something else"), e.getMessage());
        } finally {
            fake.stop(0);
        }
    }

    @Test
    void theClientOnlySpeaksHttp() {
        assertThrows(IOException.class, () -> TimeClient.request(URI.create("file:///etc/passwd"), SIG));
    }
}
