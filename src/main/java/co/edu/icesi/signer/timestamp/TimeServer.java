package co.edu.icesi.signer.timestamp;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.interfaces.RSAPrivateCrtKey;
import java.time.Clock;

/**
 * The time authority as a small HTTP service: {@code POST /stamp} with the hex SHA-256 of a
 * {@code .sig} as the body returns a signed {@link TimeToken}. Plain HTTP is enough, because
 * the token is signed: a tampered response fails verification. The authority's key stays
 * in this process's memory while it runs.
 */
public final class TimeServer implements AutoCloseable {

    public static final String PATH = "/stamp";

    /** A hex SHA-256 plus a line break, with room to spare. */
    private static final int MAX_REQUEST = 128;

    private final HttpServer server;

    private TimeServer(HttpServer server) {
        this.server = server;
    }

    /** Starts serving on {@code address}; port 0 picks a free one. */
    public static TimeServer start(InetSocketAddress address, RSAPrivateCrtKey key, Clock clock) throws IOException {
        HttpServer server = HttpServer.create(address, 0);
        server.createContext(PATH, exchange -> handle(exchange, key, clock));
        server.start();
        return new TimeServer(server);
    }

    public int port() {
        return server.getAddress().getPort();
    }

    @Override
    public void close() {
        server.stop(0);
    }

    private static void handle(HttpExchange exchange, RSAPrivateCrtKey key, Clock clock) throws IOException {
        try (exchange) {
            if (!exchange.getRequestURI().getPath().equals(PATH)) {
                respond(exchange, 404, "text/plain", "Not found\n");
                return;
            }
            if (!exchange.getRequestMethod().equals("POST")) {
                exchange.getResponseHeaders().add("Allow", "POST");
                respond(exchange, 405, "text/plain", "Use POST\n");
                return;
            }
            String body;
            try (InputStream in = exchange.getRequestBody()) {
                byte[] bytes = in.readNBytes(MAX_REQUEST + 1);
                if (bytes.length > MAX_REQUEST) {
                    respond(exchange, 413, "text/plain", "Send only the hex SHA-256 of the signature file\n");
                    return;
                }
                body = new String(bytes, StandardCharsets.US_ASCII).strip();
            }
            TimeToken token;
            try {
                token = TimeAuthority.stampHash(body, key, clock);
            } catch (IllegalArgumentException e) {
                respond(exchange, 400, "text/plain", e.getMessage() + "\n");
                return;
            } catch (GeneralSecurityException e) {
                respond(exchange, 500, "text/plain", "Could not stamp\n");
                return;
            }
            respond(exchange, 200, "application/json", new String(token.toJson(), StandardCharsets.UTF_8));
        }
    }

    private static void respond(HttpExchange exchange, int status, String type, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().add("Content-Type", type + "; charset=utf-8");
        exchange.sendResponseHeaders(status, bytes.length);
        try (OutputStream out = exchange.getResponseBody()) {
            out.write(bytes);
        }
    }
}
