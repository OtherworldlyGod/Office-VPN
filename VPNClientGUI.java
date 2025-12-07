// VPNClientGUI.java
import java.awt.*;
import java.io.*;
import java.net.*;
import java.util.List;
import java.util.concurrent.ExecutionException;
import javax.swing.*;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.SecretKey;
import java.util.Base64;

public class VPNClientGUI {
    private JCheckBox showEncryptionCheckBox;
    private JTextArea encryptionDebugArea;
    private JPanel debugPanel;
    private boolean showEncryption = false;
    private SecretKey sessionKey;
    private PublicKey serverPublicKey;
    private JFrame frame;
    private JTextArea chatArea;
    private JTextField messageField;
    private JButton connectButton, disconnectButton, sendButton, downloadButton, uploadButton;
    private Socket socket;
    private PrintWriter writer;
    private BufferedReader reader;
    private boolean isConnected = false;
    private boolean isCustomVPN = false;
    private String lastDownloadFilename = null;
    private String userEmail;

    public static void main(String[] args) {
        EventQueue.invokeLater(() -> {
            try {
                UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
                VPNClientGUI window = new VPNClientGUI();
                window.frame.setVisible(true);
            } catch (Exception e) {
                e.printStackTrace();
            }
        });
    }

    public VPNClientGUI() {
        initialize();
    }

    private void initialize() {
        frame = new JFrame("Office VPN Client");
        frame.setSize(800, 600);
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setLayout(new BorderLayout());

        JPanel connectionPanel = new JPanel();
        JTextField serverField = new JTextField("127.0.0.1", 15);
        JTextField portField = new JTextField("1194", 5);
        connectButton = new JButton("Connect");
        disconnectButton = new JButton("Disconnect");
        disconnectButton.setEnabled(false);

        connectionPanel.add(new JLabel("Server:"));
        connectionPanel.add(serverField);
        connectionPanel.add(new JLabel("Port:"));
        connectionPanel.add(portField);
        connectionPanel.add(connectButton);
        connectionPanel.add(disconnectButton);
        frame.add(connectionPanel, BorderLayout.NORTH);

        chatArea = new JTextArea();
        chatArea.setEditable(false);
        chatArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        frame.add(new JScrollPane(chatArea), BorderLayout.CENTER);

        JPanel bottomPanel = new JPanel(new BorderLayout());
        JPanel protocolPanel = new JPanel();
        protocolPanel.setBorder(BorderFactory.createTitledBorder("Protocol"));
        JRadioButton openVpnRadio = new JRadioButton("OpenVPN", true);
        JRadioButton ipsecRadio = new JRadioButton("IPSec");
        JRadioButton wireguardRadio = new JRadioButton("WireGuard");
        JRadioButton customVpnRadio = new JRadioButton("CustomVPN");
        ButtonGroup protocolGroup = new ButtonGroup();
        protocolGroup.add(openVpnRadio);
        protocolGroup.add(ipsecRadio);
        protocolGroup.add(wireguardRadio);
        protocolGroup.add(customVpnRadio);
        protocolPanel.add(openVpnRadio);
        protocolPanel.add(ipsecRadio);
        protocolPanel.add(wireguardRadio);
        protocolPanel.add(customVpnRadio);
        bottomPanel.add(protocolPanel, BorderLayout.WEST);

        JPanel messagePanel = new JPanel(new BorderLayout());
        JPanel filePanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        downloadButton = new JButton("Download");
        uploadButton = new JButton("Upload");
        downloadButton.setEnabled(false);
        uploadButton.setEnabled(false);
        filePanel.add(downloadButton);
        filePanel.add(uploadButton);
        
        messageField = new JTextField();
        sendButton = new JButton("Send");
        sendButton.setEnabled(false);
        
        messagePanel.add(filePanel, BorderLayout.WEST);
        messagePanel.add(messageField, BorderLayout.CENTER);
        messagePanel.add(sendButton, BorderLayout.EAST);
        bottomPanel.add(messagePanel, BorderLayout.CENTER);

        frame.add(bottomPanel, BorderLayout.SOUTH);

        // Action Listeners
        connectButton.addActionListener(e -> connectToServer(
            serverField.getText().trim(),
            Integer.parseInt(portField.getText().trim()),
            customVpnRadio.isSelected()
        ));
        disconnectButton.addActionListener(e -> disconnectFromServer());
        sendButton.addActionListener(e -> sendMessage());
        downloadButton.addActionListener(e -> initiateFileDownload());
        uploadButton.addActionListener(e -> initiateFileUpload());
        messageField.addActionListener(e -> sendMessage());

        // Protocol toggle
        customVpnRadio.addActionListener(e -> isCustomVPN = true);
        openVpnRadio.addActionListener(e -> isCustomVPN = false);
        ipsecRadio.addActionListener(e -> isCustomVPN = false);
        wireguardRadio.addActionListener(e -> isCustomVPN = false);

        debugPanel = new JPanel(new BorderLayout());
        debugPanel.setBorder(BorderFactory.createTitledBorder("Encryption Debug"));
        
        showEncryptionCheckBox = new JCheckBox("Show Encryption Details");
        showEncryptionCheckBox.addActionListener(e -> {
            showEncryption = showEncryptionCheckBox.isSelected();
            debugPanel.setVisible(showEncryption);
            frame.pack();
        });
        
        encryptionDebugArea = new JTextArea(6, 50);
        encryptionDebugArea.setEditable(false);
        encryptionDebugArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 11));
        JScrollPane encryptionScroll = new JScrollPane(encryptionDebugArea);
        
        debugPanel.add(encryptionScroll, BorderLayout.CENTER);
        debugPanel.setVisible(false);
        
        connectionPanel.add(showEncryptionCheckBox);
        frame.add(debugPanel, BorderLayout.AFTER_LINE_ENDS);
    }

    private void connectToServer(String serverAddress, int port, boolean useCustomVPN) {
        SwingWorker<Boolean, String> worker = new SwingWorker<>() {
            @Override
            protected Boolean doInBackground() throws Exception {
                try {
                    socket = new Socket(serverAddress, port);
                    writer = new PrintWriter(socket.getOutputStream(), true);
                    reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
    
                    // Set up encryption
                    String serverPublicKeyBase64 = reader.readLine();
                    byte[] serverPublicKeyBytes = Base64.getDecoder().decode(serverPublicKeyBase64);
                    
                    KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                    serverPublicKey = keyFactory.generatePublic(new X509EncodedKeySpec(serverPublicKeyBytes));
                    
                    // Generate a random AES session key
                    sessionKey = VPNEncryption.generateAESKey();
                    
                    // Encrypt the session key with the server's public key and send it
                    String encryptedSessionKey = VPNEncryption.encryptWithRSA(
                        VPNEncryption.secretKeyToString(sessionKey), 
                        serverPublicKey
                    );
                    writer.println(encryptedSessionKey);
                    
                    publish("Secure connection established");
    
                    // First server line (encrypted)
                    String encryptedLine = reader.readLine();
                    String line = VPNEncryption.decrypt(encryptedLine, sessionKey);
                    publish(line); // e.g. "Enter username:"
    
                    // Authentication (encrypted)
                    String resp = JOptionPane.showInputDialog(frame, line);
                    String encryptedResp = VPNEncryption.encrypt(resp, sessionKey);
                    writer.println(encryptedResp);
                    
                    encryptedLine = reader.readLine();
                    line = VPNEncryption.decrypt(encryptedLine, sessionKey);
                    publish(line); // Enter password:
                    
                    resp = JOptionPane.showInputDialog(frame, line);
                    encryptedResp = VPNEncryption.encrypt(resp, sessionKey);
                    writer.println(encryptedResp);
                    
                    encryptedLine = reader.readLine();
                    line = VPNEncryption.decrypt(encryptedLine, sessionKey);
                    publish(line); // Login result
                    
                    // Email verification
                    encryptedLine = reader.readLine();
                    line = VPNEncryption.decrypt(encryptedLine, sessionKey);
                    if (line.startsWith("Enter email:")) {
                        userEmail = JOptionPane.showInputDialog(frame, line);
                        encryptedResp = VPNEncryption.encrypt(userEmail, sessionKey);
                        writer.println(encryptedResp);
                        
                        encryptedLine = reader.readLine();
                        line = VPNEncryption.decrypt(encryptedLine, sessionKey);
                        if (line.startsWith("OTP sent to")) {
                            publish(line);
                            String otp = JOptionPane.showInputDialog(frame, "Enter OTP sent to your email:");
                            encryptedResp = VPNEncryption.encrypt(otp, sessionKey);
                            writer.println(encryptedResp);
                            
                            encryptedLine = reader.readLine();
                            line = VPNEncryption.decrypt(encryptedLine, sessionKey);
                            publish(line); // OTP verification result
                            if (line.contains("OTP verification failed")) {
                                return false;
                            }
                        }
                    }
    
                    // Protocol selection (encrypted)
                    encryptedResp = VPNEncryption.encrypt(useCustomVPN ? "CustomVPN" : "OpenVPN", sessionKey);
                    writer.println(encryptedResp);
                    
                    encryptedLine = reader.readLine();
                    line = VPNEncryption.decrypt(encryptedLine, sessionKey);
                    publish(line);
    
                    // VPN password (encrypted)
                    encryptedLine = reader.readLine();
                    line = VPNEncryption.decrypt(encryptedLine, sessionKey);
                    publish(line);
                    
                    resp = JOptionPane.showInputDialog(frame, line);
                    encryptedResp = VPNEncryption.encrypt(resp, sessionKey);
                    writer.println(encryptedResp);
                    
                    encryptedLine = reader.readLine();
                    line = VPNEncryption.decrypt(encryptedLine, sessionKey);
                    publish(line);
    
                    // Assigned IP and ready (encrypted)
                    encryptedLine = reader.readLine();
                    line = VPNEncryption.decrypt(encryptedLine, sessionKey);
                    publish(line);
                    
                    encryptedLine = reader.readLine();
                    line = VPNEncryption.decrypt(encryptedLine, sessionKey);
                    publish(line);
    
                    return true;
                } catch (Exception ex) {
                    publish("Connection error: " + ex.getMessage());
                    return false;
                }
            }
            
            @Override
            protected void process(List<String> chunks) {
                chunks.forEach(thisMsg -> appendToChat("Server: " + thisMsg));
            }
            
            @Override
            protected void done() {
                try {
                    if (get()) {
                        isConnected = true;
                        connectButton.setEnabled(false);
                        disconnectButton.setEnabled(true);
                        sendButton.setEnabled(true);
                        downloadButton.setEnabled(true);
                        uploadButton.setEnabled(true);
                        new Thread(() -> listenForMessages()).start();
                    }
                } catch (InterruptedException | ExecutionException ignored) {}
            }
        };
        worker.execute();
    }

    private void logEncryption(String plaintext, String encrypted) {
        if (!showEncryption) return;
        
        SwingUtilities.invokeLater(() -> {
            encryptionDebugArea.append("-------------------\n");
            encryptionDebugArea.append("PLAINTEXT:\n" + plaintext + "\n\n");
            encryptionDebugArea.append("ENCRYPTED:\n" + encrypted + "\n");
            encryptionDebugArea.append("-------------------\n\n");
            encryptionDebugArea.setCaretPosition(encryptionDebugArea.getDocument().getLength());
        });
    }

    private void disconnectFromServer() {
        if (!isConnected) return;
        try {
            writer.println("exit");
            socket.close();
        } catch (IOException ex) {
            appendToChat("Error disconnecting: " + ex.getMessage());
        } finally {
            isConnected = false;
            connectButton.setEnabled(true);
            disconnectButton.setEnabled(false);
            sendButton.setEnabled(false);
            downloadButton.setEnabled(false);
            uploadButton.setEnabled(false);
            appendToChat("Disconnected from server");
        }
    }

    private void sendMessage() {
        if (!isConnected) return;
        String plain = messageField.getText().trim();
        if (plain.isEmpty()) return;
        
        try {
            String prepared = plain;
            if (isCustomVPN) prepared = new StringBuilder(plain).reverse().toString();
            
            String encrypted = VPNEncryption.encrypt(prepared, sessionKey);
            logEncryption(plain + (isCustomVPN ? " (CustomVPN reversed: " + prepared + ")" : ""), encrypted);
            
            writer.println(encrypted);
            appendToChat("You: " + plain);
            messageField.setText("");
        } catch (Exception ex) {
            appendToChat("Error sending message: " + ex.getMessage());
        }
    }

    private void initiateFileDownload() {
        if (!isConnected) return;
        String filename = JOptionPane.showInputDialog(frame, "Enter filename to download:");
        if (filename == null || filename.trim().isEmpty()) return;
        
        lastDownloadFilename = filename.trim();
        try {
            String cmd = "download " + lastDownloadFilename;
            if (isCustomVPN) cmd = new StringBuilder(cmd).reverse().toString();
            
            String encrypted = VPNEncryption.encrypt(cmd, sessionKey);
            logEncryption("Download command: " + cmd, encrypted);
            
            writer.println(encrypted);
            appendToChat("You: Requested file " + lastDownloadFilename);
        } catch (Exception ex) {
            appendToChat("Error requesting file: " + ex.getMessage());
        }
    }

    private void initiateFileUpload() {
        if (!isConnected) return;
        
        JFileChooser fileChooser = new JFileChooser();
        int result = fileChooser.showOpenDialog(frame);
        
        if (result != JFileChooser.APPROVE_OPTION) {
            return;
        }
        
        File selectedFile = fileChooser.getSelectedFile();
        
        try {
            // Send upload command
            String cmd = "upload " + selectedFile.getName();
            if (isCustomVPN) cmd = new StringBuilder(cmd).reverse().toString();
            
            String encrypted = VPNEncryption.encrypt(cmd, sessionKey);
            logEncryption("Upload command: " + cmd, encrypted);
            
            writer.println(encrypted);
            appendToChat("You: Uploading file " + selectedFile.getName());
            
            // Start sending file content
            try (BufferedReader fileReader = new BufferedReader(new FileReader(selectedFile))) {
                String line;
                while ((line = fileReader.readLine()) != null) {
                    String preparedLine = line;
                    if (isCustomVPN) preparedLine = new StringBuilder(line).reverse().toString();
                    
                    String encryptedLine = VPNEncryption.encrypt(preparedLine, sessionKey);
                    writer.println(encryptedLine);
                }
            }
            
            // Send file end marker
            String endMarker = "FILE_END";
            if (isCustomVPN) endMarker = new StringBuilder(endMarker).reverse().toString();
            writer.println(VPNEncryption.encrypt(endMarker, sessionKey));
            
            appendToChat("File upload completed for " + selectedFile.getName());
            
        } catch (Exception ex) {
            appendToChat("Error uploading file: " + ex.getMessage());
        }
    }

    private void listenForMessages() {
        try {
            String encryptedLine;
            while (isConnected && (encryptedLine = reader.readLine()) != null) {
                String decrypted = VPNEncryption.decrypt(encryptedLine, sessionKey);
                
                if (showEncryption) {
                    logEncryption("RECEIVED ENCRYPTED:\n" + encryptedLine, "DECRYPTED:\n" + decrypted);
                }
                
                if (decrypted.equals("FILE_NOT_FOUND")) {
                    appendToChat("Server: File not found");
                } else if (decrypted.equals("FILE_START")) {
                    receiveEncryptedFile();
                } else if (decrypted.equals("UPLOAD_SUCCESS")) {
                    appendToChat("Server: File upload successful");
                } else if (decrypted.equals("UPLOAD_FAILED")) {
                    appendToChat("Server: File upload failed");
                } else {
                    String plain = decrypted;
                    if (isCustomVPN) plain = new StringBuilder(decrypted).reverse().toString();
                    appendToChat("Server: " + plain);
                }
            }
        } catch (Exception ex) {
            if (isConnected) {
                appendToChat("Connection error: " + ex.getMessage());
                disconnectFromServer();
            }
        }
    }

    private void receiveEncryptedFile() throws Exception {
        JFileChooser chooser = new JFileChooser();
        chooser.setSelectedFile(new File(lastDownloadFilename));
        int option = chooser.showSaveDialog(frame);
        if (option != JFileChooser.APPROVE_OPTION) {
            String encryptedLine;
            while (!(VPNEncryption.decrypt(encryptedLine = reader.readLine(), sessionKey)).equals("FILE_END"));
            appendToChat("Download canceled");
            return;
        }
        
        File outFile = chooser.getSelectedFile();
        try (BufferedWriter fw = new BufferedWriter(new FileWriter(outFile))) {
            String encryptedLine;
            while (!(VPNEncryption.decrypt(encryptedLine = reader.readLine(), sessionKey)).equals("FILE_END")) {
                String decrypted = VPNEncryption.decrypt(encryptedLine, sessionKey);
                String plain = isCustomVPN ? new StringBuilder(decrypted).reverse().toString() : decrypted;
                fw.write(plain);
                fw.newLine();
            }
        }
        appendToChat("File downloaded to: " + outFile.getAbsolutePath());
    }

    private void appendToChat(String text) {
        SwingUtilities.invokeLater(() -> {
            chatArea.append(text + "\n");
            chatArea.setCaretPosition(chatArea.getDocument().getLength());
        });
    }
}