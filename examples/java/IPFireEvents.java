import java.io.BufferedReader;
import java.io.Console;
import java.io.InputStreamReader;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpClient;
import java.net.http.WebSocket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.time.Duration;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

public final class IPFireEvents {
    enum Topic {
        SYSTEM("watch-1", "system.info"),
        RED("watch-red", "red.status");

        private final String request;

        Topic(String id, String event) {
            request = "{\"id\":\"" + id + "\",\"method\":\"events.subscribe\",\"params\":{\"event\":\"" + event + "\"}}";
        }
    }

    static void subscribe(WebSocket socket, Topic... topics) throws Exception {
        for (Topic topic : topics) {
            socket.sendText(topic.request, true).get(5, TimeUnit.SECONDS);
        }
    }

    public static void main(String[] args) throws Exception {
        if (args.length == 0) {
            IPFireEventsWindow.open();
            return;
        }
        if (args.length > 2) {
            System.err.println("Usage: java -jar ipfire-events.jar <wss-url> [trusted-certificate.pem]");
            System.exit(2);
        }
        EventListener listener = new EventListener(System.out::println);
        WebSocket socket = connect(args[0], args.length == 2 ? args[1] : "", readToken(), listener);

        Runtime.getRuntime().addShutdownHook(new Thread(() -> close(socket, listener)));
        try {
            subscribe(socket, Topic.values());
            listener.closed.get();
        } finally {
            socket.abort();
        }
    }

    static WebSocket connect(String url, String certificate, String token, EventListener listener) throws Exception {
        URI uri = new URI(url);
        if (!"wss".equalsIgnoreCase(uri.getScheme()) || uri.getHost() == null
                || uri.getRawUserInfo() != null || uri.getRawFragment() != null) {
            throw new URISyntaxException("WebSocket URL", "Expected a wss URL with a hostname");
        }
        String authorization = "Bearer " + validateToken(token);

        HttpClient.Builder client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10));
        if (!certificate.isEmpty()) {
            client.sslContext(tlsWithCertificate(Path.of(certificate)));
        }
        CompletableFuture<WebSocket> opening = client.build().newWebSocketBuilder()
            .header("Authorization", authorization)
            .buildAsync(uri, listener);
        try {
            return opening.get(10, TimeUnit.SECONDS);
        } catch (InterruptedException | TimeoutException error) {
            opening.thenAccept(WebSocket::abort);
            throw error;
        }
    }

    private static String readToken() throws Exception {
        Console console = System.console();
        char[] password = console == null ? null : console.readPassword("IPFire API token: ");
        String token;
        if (console == null) {
            token = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8)).readLine();
        } else {
            token = password == null ? null : new String(password);
            if (password != null) {
                java.util.Arrays.fill(password, '\0');
            }
        }
        return token;
    }

    private static String validateToken(String token) {
        String normalized = token == null ? "" : token.replaceAll("(?U)\\A\\s+|\\s+\\z", "");
        if (!normalized.matches("[a-z0-9][a-z0-9_-]{0,63}\\.[0-9a-f]{64}")) {
            throw new InvalidTokenException();
        }
        return normalized;
    }

    static final class InvalidTokenException extends IllegalArgumentException {
        private static final long serialVersionUID = 1L;

        InvalidTokenException() {
            super("Expected a valid IPFire API token");
        }
    }

    private static SSLContext tlsWithCertificate(Path path) throws Exception {
        Certificate certificate;
        try (var input = Files.newInputStream(path)) {
            certificate = CertificateFactory.getInstance("X.509").generateCertificate(input);
        }
        KeyStore trust = KeyStore.getInstance(KeyStore.getDefaultType());
        trust.load(null, null);
        trust.setCertificateEntry("ipfire", certificate);
        TrustManagerFactory managers = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        managers.init(trust);
        SSLContext tls = SSLContext.getInstance("TLS");
        tls.init(null, managers.getTrustManagers(), null);
        return tls;
    }

    static void close(WebSocket socket, EventListener listener) {
        if (socket.isOutputClosed()) {
            return;
        }
        try {
            socket.sendClose(WebSocket.NORMAL_CLOSURE, "Client stopped").get(2, TimeUnit.SECONDS);
            listener.closed.get(2, TimeUnit.SECONDS);
        } catch (Exception ignored) {
            socket.abort();
        }
    }

    static final class EventListener implements WebSocket.Listener {
        private final StringBuilder message = new StringBuilder();
        final CompletableFuture<Void> closed = new CompletableFuture<>();
        private final Consumer<String> output;

        EventListener(Consumer<String> output) {
            this.output = output;
        }

        @Override
        public CompletionStage<?> onText(WebSocket socket, CharSequence data, boolean last) {
            if (message.length() + data.length() > 65536) {
                socket.abort();
                closed.completeExceptionally(new IllegalStateException("API message exceeds 65536 characters"));
                return null;
            }
            message.append(data);
            if (last) {
                output.accept(message.toString());
                message.setLength(0);
            }
            socket.request(1);
            return null;
        }

        @Override
        public CompletionStage<?> onClose(WebSocket socket, int code, String reason) {
            closed.complete(null);
            return null;
        }

        @Override
        public void onError(WebSocket socket, Throwable error) {
            closed.completeExceptionally(error);
        }
    }
}
