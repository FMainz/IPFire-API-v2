import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.io.IOException;
import java.net.URISyntaxException;
import java.net.http.WebSocket;
import java.net.http.WebSocketHandshakeException;
import java.util.Arrays;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeoutException;
import javax.net.ssl.SSLException;
import javax.swing.BorderFactory;
import javax.swing.ButtonGroup;
import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JRadioButton;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;
import javax.swing.SwingWorker;
import javax.swing.Timer;
import javax.swing.filechooser.FileNameExtensionFilter;

final class IPFireEventsWindow extends JPanel {
    private static final long serialVersionUID = 1L;
    private static final int OUTPUT_LIMIT = 100_000;

    private final JTextField address = new JTextField("wss://", 32);
    private final JTextField certificate = new JTextField(32);
    private final JPasswordField token = new JPasswordField(32);
    private final JButton browse = new JButton("Auswählen …");
    private final JButton toggle = new JButton("Verbinden");
    private final JLabel status = new JLabel("Getrennt");
    private final JTextArea output = new JTextArea(16, 64);
    private final JRadioButton allTopics = new JRadioButton("Alle verfügbaren", true);
    private final JRadioButton systemTopic = new JRadioButton("System");
    private final JRadioButton redTopic = new JRadioButton("RED-Status");
    private transient WebSocket socket;
    private transient IPFireEvents.EventListener connectedListener;
    private transient Session session;
    private final Timer retryTimer = new Timer(0, event -> openConnection(session));

    private static final class Session {
        final String url;
        final String certificatePath;
        final IPFireEvents.Topic[] topics;
        volatile boolean cancelled;
        boolean connectedBefore;
        int retrySeconds = 1;

        Session(String url, String certificatePath, IPFireEvents.Topic[] topics) {
            this.url = url;
            this.certificatePath = certificatePath;
            this.topics = topics;
        }
    }

    static void open() {
        SwingUtilities.invokeLater(() -> {
            JFrame frame = new JFrame("IPFire API v2");
            frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
            frame.setContentPane(new IPFireEventsWindow());
            frame.pack();
            frame.setLocationByPlatform(true);
            frame.setVisible(true);
        });
    }

    IPFireEventsWindow() {
        super(new BorderLayout(0, 12));
        setBorder(BorderFactory.createEmptyBorder(16, 16, 16, 16));
        retryTimer.setRepeats(false);

        JPanel form = new JPanel(new GridBagLayout());
        addField(form, 0, "WebSocket-URL", address);
        addField(form, 1, "Zertifikat (optional)", certificate);
        addField(form, 2, "API-Token", token);
        GridBagConstraints browsePosition = new GridBagConstraints();
        browsePosition.gridx = 2;
        browsePosition.gridy = 1;
        form.add(browse, browsePosition);
        browse.addActionListener(event -> selectCertificate());
        add(form, BorderLayout.NORTH);

        output.setEditable(false);
        output.setLineWrap(true);
        output.setWrapStyleWord(true);
        output.setFont(new Font(Font.MONOSPACED, Font.PLAIN, output.getFont().getSize()));
        JScrollPane messages = new JScrollPane(output);
        messages.setBorder(BorderFactory.createTitledBorder("API-Nachrichten"));
        JPanel monitor = new JPanel(new BorderLayout(0, 6));
        monitor.add(createTopicSelector(), BorderLayout.NORTH);
        monitor.add(messages, BorderLayout.CENTER);
        add(monitor, BorderLayout.CENTER);

        JPanel actions = new JPanel(new BorderLayout(12, 0));
        actions.add(status, BorderLayout.CENTER);
        actions.add(toggle, BorderLayout.EAST);
        add(actions, BorderLayout.SOUTH);
        toggle.addActionListener(event -> {
            if (session == null) {
                connect();
            } else {
                disconnect();
            }
        });
        token.addActionListener(event -> {
            if (session == null && toggle.isEnabled()) {
                connect();
            }
        });
    }

    private JScrollPane createTopicSelector() {
        JPanel topics = new JPanel(new FlowLayout(FlowLayout.LEADING, 4, 0));
        topics.add(new JLabel("Abonnieren:"));
        ButtonGroup selection = new ButtonGroup();
        for (JRadioButton option : new JRadioButton[] {allTopics, systemTopic, redTopic}) {
            selection.add(option);
            topics.add(option);
        }
        systemTopic.setToolTipText("system.info");
        redTopic.setToolTipText("red.status");
        for (String name : new String[] {"Updates", "Netzwerk", "DHCP", "Dienste", "Add-ons", "Verkehr"}) {
            JRadioButton option = new JRadioButton(name);
            option.setEnabled(false);
            option.setToolTipText("In API v2 noch nicht verfügbar");
            selection.add(option);
            topics.add(option);
        }

        JScrollPane scroller = new JScrollPane(
            topics, JScrollPane.VERTICAL_SCROLLBAR_NEVER, JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
        scroller.setBorder(BorderFactory.createEmptyBorder());
        int height = topics.getPreferredSize().height + scroller.getHorizontalScrollBar().getPreferredSize().height;
        scroller.setPreferredSize(new Dimension(output.getPreferredScrollableViewportSize().width, height));
        return scroller;
    }

    private static void addField(JPanel form, int row, String name, JTextField input) {
        GridBagConstraints position = new GridBagConstraints();
        position.gridx = 0;
        position.gridy = row;
        position.anchor = GridBagConstraints.LINE_START;
        position.insets = new Insets(4, 0, 4, 10);
        JLabel label = new JLabel(name);
        label.setLabelFor(input);
        form.add(label, position);
        position.gridx = 1;
        position.weightx = 1;
        position.fill = GridBagConstraints.HORIZONTAL;
        form.add(input, position);
    }

    private void selectCertificate() {
        JFileChooser chooser = certificateChooser();
        if (chooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            certificate.setText(chooser.getSelectedFile().getAbsolutePath());
        }
    }

    static JFileChooser certificateChooser() {
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Öffentliche Zertifikatsdatei auswählen");
        chooser.setFileFilter(new FileNameExtensionFilter("PEM-Zertifikate (*.pem)", "pem"));
        return chooser;
    }

    private void connect() {
        IPFireEvents.Topic[] topics;
        if (systemTopic.isSelected()) {
            topics = new IPFireEvents.Topic[] {IPFireEvents.Topic.SYSTEM};
        } else if (redTopic.isSelected()) {
            topics = new IPFireEvents.Topic[] {IPFireEvents.Topic.RED};
        } else {
            topics = IPFireEvents.Topic.values();
        }
        session = new Session(address.getText().trim(), certificate.getText().trim(), topics);
        setFieldsEnabled(false);
        toggle.setText("Trennen");
        openConnection(session);
    }

    private void openConnection(Session current) {
        if (current == null || current.cancelled) {
            return;
        }
        char[] password = token.getPassword();
        IPFireEvents.EventListener listener = new IPFireEvents.EventListener(
            message -> SwingUtilities.invokeLater(() -> {
                if (session == current) {
                    append(message);
                }
            }));
        status.setText("Verbindung wird aufgebaut …");

        new SwingWorker<WebSocket, Void>() {
            @Override
            protected WebSocket doInBackground() throws Exception {
                WebSocket connected;
                try {
                    connected = IPFireEvents.connect(
                        current.url, current.certificatePath, new String(password), listener);
                } finally {
                    Arrays.fill(password, '\0');
                }
                try {
                    if (current.cancelled) {
                        connected.abort();
                    } else {
                        IPFireEvents.subscribe(connected, current.topics);
                    }
                    return connected;
                } catch (Exception error) {
                    connected.abort();
                    throw error;
                }
            }

            @Override
            protected void done() {
                WebSocket connected;
                try {
                    connected = get();
                } catch (InterruptedException error) {
                    Thread.currentThread().interrupt();
                    if (session == current) {
                        showDisconnected("Getrennt");
                    }
                    return;
                } catch (ExecutionException error) {
                    if (session == current) {
                        if (current.connectedBefore && canRetry(error)) {
                            scheduleRetry(current);
                        } else {
                            showDisconnected(connectionError(error));
                        }
                    }
                    return;
                }
                if (session != current) {
                    connected.abort();
                    return;
                }
                socket = connected;
                connectedListener = listener;
                current.connectedBefore = true;
                current.retrySeconds = 1;
                status.setText("Verbunden");
                listener.closed.whenComplete((ignored, error) -> SwingUtilities.invokeLater(() -> {
                    if (session == current && socket == connected) {
                        socket = null;
                        connectedListener = null;
                        scheduleRetry(current);
                    }
                }));
            }
        }.execute();
    }

    private void scheduleRetry(Session current) {
        int seconds = current.retrySeconds;
        status.setText("Verbindung unterbrochen. Neuer Versuch in " + seconds + " s …");
        retryTimer.setInitialDelay(seconds * 1000);
        retryTimer.restart();
        current.retrySeconds = Math.min(seconds * 2, 30);
    }

    private void disconnect() {
        WebSocket closing = socket;
        IPFireEvents.EventListener listener = connectedListener;
        session.cancelled = true;
        session = null;
        retryTimer.stop();
        if (closing == null) {
            showDisconnected("Getrennt");
            return;
        }
        toggle.setEnabled(false);
        status.setText("Verbindung wird getrennt …");
        CompletableFuture.runAsync(() -> IPFireEvents.close(closing, listener))
            .whenComplete((ignored, error) -> SwingUtilities.invokeLater(() -> showDisconnected("Getrennt")));
    }

    private void showDisconnected(String message) {
        session = null;
        retryTimer.stop();
        socket = null;
        connectedListener = null;
        setFieldsEnabled(true);
        toggle.setText("Verbinden");
        toggle.setEnabled(true);
        status.setText(message);
    }

    private static boolean canRetry(Throwable error) {
        boolean transientFailure = false;
        for (Throwable cause = error; cause != null; cause = cause.getCause()) {
            if (cause instanceof SSLException || cause instanceof java.nio.file.FileSystemException) {
                return false;
            }
            if (cause instanceof WebSocketHandshakeException) {
                int code = ((WebSocketHandshakeException) cause).getResponse().statusCode();
                return code == 429 || code >= 500;
            }
            if (cause instanceof IOException || cause instanceof TimeoutException) {
                transientFailure = true;
            }
        }
        return transientFailure;
    }

    private void setFieldsEnabled(boolean enabled) {
        address.setEnabled(enabled);
        certificate.setEnabled(enabled);
        token.setEnabled(enabled);
        browse.setEnabled(enabled);
        allTopics.setEnabled(enabled);
        systemTopic.setEnabled(enabled);
        redTopic.setEnabled(enabled);
    }

    private void append(String message) {
        output.append(message + "\n");
        if (output.getDocument().getLength() > OUTPUT_LIMIT) {
            int excess = output.getDocument().getLength() - OUTPUT_LIMIT;
            int newline = output.getText().indexOf('\n', excess);
            output.replaceRange("", 0, newline + 1);
        }
        output.setCaretPosition(output.getDocument().getLength());
    }

    private static String connectionError(Throwable error) {
        for (Throwable cause = error; cause != null; cause = cause.getCause()) {
            if (cause instanceof SSLException) {
                return "TLS-Prüfung fehlgeschlagen. Hostnamen und Zertifikat prüfen.";
            }
            if (cause instanceof WebSocketHandshakeException) {
                int code = ((WebSocketHandshakeException) cause).getResponse().statusCode();
                return code == 401 ? "API-Token wurde abgelehnt." : "WebSocket-Anfrage abgelehnt (HTTP " + code + ").";
            }
            if (cause instanceof IPFireEvents.InvalidTokenException) {
                return "API-Token unvollständig oder ungültig. Vollständigen Token einfügen.";
            }
            if (cause instanceof URISyntaxException) {
                return "Ungültige WebSocket-URL. Erwartet wird wss://Hostname:8444/.";
            }
            if (cause instanceof java.nio.file.InvalidPathException
                    || cause instanceof java.nio.file.FileSystemException
                    || cause instanceof java.security.cert.CertificateException) {
                return "Zertifikatsdatei konnte nicht gelesen werden.";
            }
        }
        return "Verbindung fehlgeschlagen. Adresse und API-Dienst prüfen.";
    }
}
