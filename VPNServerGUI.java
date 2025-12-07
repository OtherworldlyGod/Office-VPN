// VPNServerGUI.java
import java.awt.*;
import java.io.*;
import java.net.*;
import java.security.*;
import java.util.*;
import java.util.Queue;
import java.util.concurrent.*;
import javax.crypto.SecretKey;
import javax.swing.*;
import javax.mail.*;
import javax.mail.internet.*;
import java.nio.file.*;

public class VPNServerGUI {
    private static final int PORT = 1194;
    private Set<String> allowedIPs = Collections.newSetFromMap(new ConcurrentHashMap<>());
    private IPPool ipPool = new IPPool("10.8.0.", 2, 254);
    private NATManager natManager = new NATManager();
    private TrafficAnalytics analytics = new TrafficAnalytics();
    private ExecutorService executor = Executors.newFixedThreadPool(5);
    private Map<String, String> credentials = new ConcurrentHashMap<>();
    private Map<String, String> userEmails = new ConcurrentHashMap<>();
    private Map<String, String> otpStore = new ConcurrentHashMap<>();
    private KeyPair serverKeyPair;
    private Map<String, SecretKey> clientSessionKeys = new ConcurrentHashMap<>();

    private JFrame frame;
    private JTextArea logArea;
    private JButton startButton, stopButton, viewUsersButton;
    private ServerSocket serverSocket;
    private boolean isRunning = false;
    private ScheduledExecutorService scheduler;
    private File usersFile;

    // Email configuration
    private final String emailHost = "smtp.gmail.com";
    private final String emailPort = "587";
    private final String emailUsername = "vedantwade746@gmail.com";
    private final String emailPassword = "qyse nacn hcwc gnlf";

    public static void main(String[] args) {
        EventQueue.invokeLater(() -> {
            try {
                UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
                new VPNServerGUI().frame.setVisible(true);
            } catch (Exception e) {
                e.printStackTrace();
            }
        });
    }

    public VPNServerGUI() {
        allowedIPs.add("127.0.0.1");
        initUI();
        loadCredentials();
        initEncryption();
        createSharedFolder();
    }

    private void initUI() {
        frame = new JFrame("Office VPN Server");
        frame.setSize(900, 600);
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setLayout(new BorderLayout());

        JPanel control = new JPanel();
        startButton = new JButton("Start Server");
        stopButton = new JButton("Stop Server");
        viewUsersButton = new JButton("View Users");
        
        stopButton.setEnabled(false);
        startButton.addActionListener(e -> startServer());
        stopButton.addActionListener(e -> stopServer());
        viewUsersButton.addActionListener(e -> viewUsersCSV());
        
        control.add(startButton);
        control.add(stopButton);
        control.add(viewUsersButton);

        JTextField ipField = new JTextField(10);
        JButton addIpButton = new JButton("Add Allowed IP");
        addIpButton.addActionListener(e -> {
            String ip = ipField.getText().trim();
            if (isValidIP(ip)) {
                allowedIPs.add(ip);
                log("Added allowed IP: " + ip);
            } else {
                log("Invalid IP format: " + ip);
            }
            ipField.setText("");
        });
        control.add(new JLabel("Allowed IP:"));
        control.add(ipField);
        control.add(addIpButton);

        frame.add(control, BorderLayout.NORTH);

        logArea = new JTextArea();
        logArea.setEditable(false);
        logArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        frame.add(new JScrollPane(logArea), BorderLayout.CENTER);

        JLabel status = new JLabel("Server Status: Stopped");
        JPanel statusPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        statusPanel.add(status);
        frame.add(statusPanel, BorderLayout.SOUTH);
    }

    private void initEncryption() {
        try {
            serverKeyPair = VPNEncryption.generateRSAKeyPair();
            log("Server encryption keys generated");
        } catch (NoSuchAlgorithmException e) {
            log("Error initializing encryption: " + e.getMessage());
        }
    }

    private void startServer() {
        if (isRunning) return;
        log("Starting VPN Server on port " + PORT);
        isRunning = true;
        startButton.setEnabled(false);
        stopButton.setEnabled(true);

        scheduler = Executors.newScheduledThreadPool(1);
        scheduler.scheduleAtFixedRate(() -> analytics.print(this), 30, 30, TimeUnit.SECONDS);

        new Thread(() -> {
            try {
                serverSocket = new ServerSocket(PORT);
                while (isRunning) {
                    Socket client = serverSocket.accept();
                    String ip = client.getInetAddress().getHostAddress();
                    if (!allowedIPs.contains(ip)) {
                        log("IP out of access: " + ip);
                        try (PrintWriter w = new PrintWriter(client.getOutputStream(), true)) {
                            w.println("Access denied: IP out of allowed range");
                        }
                        client.close();
                        continue;
                    }
                    log("Connected: " + ip);
                    executor.submit(new ClientHandler(client));
                }
            } catch (IOException e) {
                if (isRunning) log("Server error: " + e.getMessage());
            }
        }, "Accept-Thread").start();
    }

    private void stopServer() {
        if (!isRunning) return;
        log("Stopping VPN Server...");
        isRunning = false;
        startButton.setEnabled(true);
        stopButton.setEnabled(false);
        try {
            if (serverSocket != null) serverSocket.close();
            executor.shutdownNow();
            scheduler.shutdownNow();
        } catch (IOException ignored) {}
    }

    public void log(String msg) {
        SwingUtilities.invokeLater(() -> {
            logArea.append(String.format("[%tT] %s\n", new Date(), msg));
            logArea.setCaretPosition(logArea.getDocument().getLength());
        });
    }

    private boolean isValidIP(String ip) {
        return ip.matches("^(25[0-5]|2[0-4]\\d|1?\\d?\\d)(\\.(25[0-5]|2[0-4]\\d|1?\\d?\\d)){3}$");
    }

    private void loadCredentials() {
        usersFile = new File("users.csv");
        if (!usersFile.exists()) try (FileWriter fw = new FileWriter(usersFile)) {
            fw.write("username,password,email\nadmin,admin123,admin@example.com\nuser,user123,user@example.com\n");
            log("Created default users.csv");
        } catch (IOException e) { log("Error: " + e.getMessage()); }
        try (BufferedReader br = new BufferedReader(new FileReader(usersFile))) {
            br.readLine(); // Skip header
            String l;
            while ((l = br.readLine()) != null) {
                String[] p = l.split(",");
                if (p.length >= 3) {
                    credentials.put(p[0], p[1]);
                    userEmails.put(p[0], p[2]);
                }
            }
            log("Loaded " + credentials.size() + " users");
        } catch (IOException e) { log("Error: " + e.getMessage()); }
    }

    private void viewUsersCSV() {
        try {
            StringBuilder content = new StringBuilder();
            
            try (BufferedReader br = new BufferedReader(new FileReader(usersFile))) {
                String line;
                while ((line = br.readLine()) != null) {
                    content.append(line).append("\n");
                }
            }
            
            JTextArea textArea = new JTextArea(content.toString());
            textArea.setEditable(false);
            textArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
            
            JScrollPane scrollPane = new JScrollPane(textArea);
            scrollPane.setPreferredSize(new Dimension(500, 300));
            
            JDialog dialog = new JDialog(frame, "User Credentials (users.csv)", true);
            dialog.setLayout(new BorderLayout());
            dialog.add(scrollPane, BorderLayout.CENTER);
            
            JPanel buttonPanel = new JPanel();
            JButton closeButton = new JButton("Close");
            JButton editButton = new JButton("Edit Users");
            
            closeButton.addActionListener(e -> dialog.dispose());
            editButton.addActionListener(e -> editUsersCSV(dialog));
            
            buttonPanel.add(closeButton);
            buttonPanel.add(editButton);
            dialog.add(buttonPanel, BorderLayout.SOUTH);
            
            dialog.pack();
            dialog.setLocationRelativeTo(frame);
            dialog.setVisible(true);
            
        } catch (IOException e) {
            log("Error reading users.csv: " + e.getMessage());
            JOptionPane.showMessageDialog(frame, "Error reading users.csv: " + e.getMessage(), 
                    "Error", JOptionPane.ERROR_MESSAGE);
        }
    }
    
    private void editUsersCSV(JDialog parentDialog) {
        try {
            StringBuilder content = new StringBuilder();
            
            try (BufferedReader br = new BufferedReader(new FileReader(usersFile))) {
                String line;
                while ((line = br.readLine()) != null) {
                    content.append(line).append("\n");
                }
            }
            
            JTextArea editArea = new JTextArea(content.toString());
            editArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
            
            JScrollPane scrollPane = new JScrollPane(editArea);
            scrollPane.setPreferredSize(new Dimension(500, 300));
            
            JDialog editDialog = new JDialog(frame, "Edit User Credentials", true);
            editDialog.setLayout(new BorderLayout());
            editDialog.add(scrollPane, BorderLayout.CENTER);
            
            JPanel buttonPanel = new JPanel();
            JButton cancelButton = new JButton("Cancel");
            JButton saveButton = new JButton("Save");
            
            cancelButton.addActionListener(e -> editDialog.dispose());
            
            saveButton.addActionListener(e -> {
                try (FileWriter fw = new FileWriter(usersFile)) {
                    fw.write(editArea.getText());
                    log("User credentials updated");
                    editDialog.dispose();
                    if (parentDialog != null) {
                        parentDialog.dispose();
                    }
                    // Reload credentials
                    credentials.clear();
                    userEmails.clear();
                    loadCredentials();
                    // Show updated view
                    viewUsersCSV();
                } catch (IOException ex) {
                    log("Error saving users.csv: " + ex.getMessage());
                    JOptionPane.showMessageDialog(editDialog, "Error saving users.csv: " + ex.getMessage(),
                            "Error", JOptionPane.ERROR_MESSAGE);
                }
            });
            
            buttonPanel.add(cancelButton);
            buttonPanel.add(saveButton);
            editDialog.add(buttonPanel, BorderLayout.SOUTH);
            
            editDialog.pack();
            editDialog.setLocationRelativeTo(frame);
            editDialog.setVisible(true);
            
        } catch (IOException e) {
            log("Error reading users.csv for editing: " + e.getMessage());
            JOptionPane.showMessageDialog(frame, "Error reading users.csv: " + e.getMessage(), 
                    "Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void createSharedFolder() {
        File d = new File("shared");
        if (!d.exists() && d.mkdir()) {
            try (FileWriter w = new FileWriter(new File(d, "sample.txt"))) {
                w.write("Sample file for VPN\nLine1\nLine2");
            } catch (IOException e) {
                log("Error: " + e.getMessage());
            }
        }
    }

    private void sendOTPEmail(String email, String otp) {
        Properties props = new Properties();
        props.put("mail.smtp.auth", "true");
        props.put("mail.smtp.starttls.enable", "true");
        props.put("mail.smtp.host", emailHost);
        props.put("mail.smtp.port", emailPort);

        // Use fully qualified names
        Session session = Session.getInstance(props, new javax.mail.Authenticator() {
            protected javax.mail.PasswordAuthentication getPasswordAuthentication() {
                return new javax.mail.PasswordAuthentication(emailUsername, emailPassword);
            }
        });

        try {
            Message message = new MimeMessage(session);
            message.setFrom(new InternetAddress(emailUsername));
            message.setRecipients(Message.RecipientType.TO, InternetAddress.parse(email));
            message.setSubject("Your VPN OTP Code");
            message.setText("Your OTP code is: " + otp + "\nThis code will expire in 5 minutes.");
            Transport.send(message);
            log("OTP sent to " + email);
        } catch (MessagingException e) {
            log("Failed to send OTP email: " + e.getMessage());
        }
    }

    private String generateOTP() {
        Random random = new Random();
        int otp = 100000 + random.nextInt(900000);
        return String.valueOf(otp);
    }

    class IPPool {
        private Queue<String> free = new LinkedList<>();
        private Set<String> used = new HashSet<>();
        IPPool(String base, int start, int end) {
            for (int i = start; i <= end; i++) free.add(base + i);
        }
        synchronized String assign() {
            String ip = free.poll(); if (ip != null) used.add(ip); return ip;
        }
        synchronized void release(String ip) {
            if (used.remove(ip)) free.add(ip);
        }
    }

    class NATManager {
        private Map<String,String> table = new ConcurrentHashMap<>();
        void register(String pub, String priv) { table.put(priv,pub); log("NAT: " + priv + "->" + pub); }
        String translate(String priv) { return table.getOrDefault(priv,"?"); }
        void remove(String priv) { table.remove(priv); }
    }

    class TrafficAnalytics {
        private ConcurrentHashMap<String,Integer> counts = new ConcurrentHashMap<>();
        void record(String client, String msg) {
            int c = counts.merge(client,1,Integer::sum);
            if (c > 10) log("AI Alert: high traffic from " + client + " (" + c + ")");
        }
        void print(VPNServerGUI srv) {
            srv.log("--- Analytics Report ---");
            counts.forEach((ip,c)-> srv.log(ip + ": " + c));
            srv.log("------------------------");
        }
    }

    interface VPNProtocol { void init(); String name(); }
    class OpenVPN implements VPNProtocol { public void init() { log("Init OpenVPN"); } public String name(){return "OpenVPN";} }
    class IPSec implements VPNProtocol { public void init() { log("Init IPSec"); }  public String name(){return "IPSec";} }
    class WireGuard implements VPNProtocol { public void init() { log("Init WireGuard"); } public String name(){return "WireGuard";} }
    class CustomVPN implements VPNProtocol {
        public void init(){ log("Init CustomVPN"); }
        public String name(){ return "CustomVPN"; }
        String obf(String m){ return new StringBuilder(m).reverse().toString(); }
        String deobf(String m){ return new StringBuilder(m).reverse().toString(); }
    }

    class ClientHandler implements Runnable {
        private Socket sock;
        private String assigned;
        private VPNProtocol proto;
        private SecretKey sessionKey;
        private String clientIdentifier;
        private String username;
        
        ClientHandler(Socket s) { 
            this.sock = s; 
            this.clientIdentifier = s.getInetAddress().getHostAddress() + ":" + s.getPort();
        }
        
        public void run() {
            try (BufferedReader r = new BufferedReader(new InputStreamReader(sock.getInputStream()));
                 PrintWriter w = new PrintWriter(sock.getOutputStream(), true)) {
                
                // First, perform key exchange
                w.println(Base64.getEncoder().encodeToString(serverKeyPair.getPublic().getEncoded()));
                String encryptedSessionKeyStr = r.readLine();
                
                // Decrypt the session key sent by client
                try {
                    String sessionKeyStr = VPNEncryption.decryptWithRSA(encryptedSessionKeyStr, serverKeyPair.getPrivate());
                    sessionKey = VPNEncryption.stringToSecretKey(sessionKeyStr);
                    clientSessionKeys.put(clientIdentifier, sessionKey);
                    log("Secure session established with " + sock.getInetAddress().getHostAddress());
                } catch (Exception e) {
                    log("Encryption setup failed: " + e.getMessage());
                    return;
                }
                
                // Auth (now encrypted)
                String encryptedPrompt = VPNEncryption.encrypt("Enter username:", sessionKey);
                w.println(encryptedPrompt);
                String encryptedUsername = r.readLine();
                username = VPNEncryption.decrypt(encryptedUsername, sessionKey);
                
                encryptedPrompt = VPNEncryption.encrypt("Enter password:", sessionKey);
                w.println(encryptedPrompt);
                String encryptedPassword = r.readLine();
                String p = VPNEncryption.decrypt(encryptedPassword, sessionKey);
                
                if (!credentials.containsKey(username) || !credentials.get(username).equals(p)) {
                    w.println(VPNEncryption.encrypt("Login failed", sessionKey));
                    log("Bad login from " + sock.getInetAddress());
                    return;
                }
                w.println(VPNEncryption.encrypt("Login successful", sessionKey));
                log(username + " logged in");
                
                // Email verification
                String userEmail = userEmails.get(username);
                if (userEmail != null) {
                    String otp = generateOTP();
                    otpStore.put(username, otp);
                    
                    // Send OTP to email
                    sendOTPEmail(userEmail, otp);
                    
                    w.println(VPNEncryption.encrypt("Enter email:", sessionKey));
                    String encryptedEmail = r.readLine();
                    String email = VPNEncryption.decrypt(encryptedEmail, sessionKey);
                    
                    if (email.equalsIgnoreCase(userEmail)) {
                        w.println(VPNEncryption.encrypt("OTP sent to " + email, sessionKey));
                        
                        String encryptedOTP = r.readLine();
                        String receivedOTP = VPNEncryption.decrypt(encryptedOTP, sessionKey);
                        
                        if (receivedOTP.equals(otpStore.get(username))) {
                            w.println(VPNEncryption.encrypt("OTP verification successful", sessionKey));
                            otpStore.remove(username);
                        } else {
                            w.println(VPNEncryption.encrypt("OTP verification failed", sessionKey));
                            log("OTP verification failed for " + username);
                            return;
                        }
                    } else {
                        w.println(VPNEncryption.encrypt("Email verification failed", sessionKey));
                        return;
                    }
                }
                
                // Protocol selection (encrypted)
                w.println(VPNEncryption.encrypt("Protocol (OpenVPN/IPSec/WireGuard/CustomVPN):", sessionKey));
                String encryptedChoice = r.readLine();
                String choice = VPNEncryption.decrypt(encryptedChoice, sessionKey);
                
                switch (choice.toLowerCase()) {
                    case "ipsec": proto = new IPSec(); break;
                    case "wireguard": proto = new WireGuard(); break;
                    case "customvpn": proto = new CustomVPN(); break;
                    default: proto = new OpenVPN();
                }
                
                w.println(VPNEncryption.encrypt("Using " + proto.name(), sessionKey));
                proto.init();
                
                // VPN Password (encrypted)
                w.println(VPNEncryption.encrypt("Enter VPN pass:", sessionKey));
                String encryptedVPNPass = r.readLine();
                String vpnPass = VPNEncryption.decrypt(encryptedVPNPass, sessionKey);
                
                if (!"secure123".equals(vpnPass)) {
                    w.println(VPNEncryption.encrypt("Auth fail", sessionKey));
                    return;
                }
                w.println(VPNEncryption.encrypt("VPN OK", sessionKey));
                
                // Assign IP
                assigned = ipPool.assign();
                if (assigned == null) {
                    w.println(VPNEncryption.encrypt("No IPs", sessionKey));
                    return;
                }
                w.println(VPNEncryption.encrypt("Assigned: " + assigned, sessionKey));
                natManager.register(sock.getInetAddress().getHostAddress(), assigned);
                w.println(VPNEncryption.encrypt("Connected. Type 'download <file>', 'upload <file>', or 'exit'.", sessionKey));
                
                String encryptedLine;
                while ((encryptedLine = r.readLine()) != null) {
                    String line = VPNEncryption.decrypt(encryptedLine, sessionKey);
                    
                    if ("exit".equalsIgnoreCase(line)) break;
                    
                    if (proto instanceof CustomVPN) line = ((CustomVPN)proto).deobf(line);
                    analytics.record(assigned, line);
                    
                    if (line.startsWith("download ")) {
                        sendEncryptedFile(line.substring(9), w, proto);
                    } else if (line.startsWith("upload ")) {
                        receiveEncryptedFile(line.substring(7), r, w, proto);
                    } else {
                        String resp = "Got: " + line + " [NAT:" + natManager.translate(assigned) + "]";
                        if (proto instanceof CustomVPN) resp = ((CustomVPN)proto).obf(resp);
                        String encryptedResp = VPNEncryption.encrypt(resp, sessionKey);
                        w.println(encryptedResp);
                    }
                }
            } catch (Exception e) {
                log("Client err: " + e.getMessage());
            } finally {
                cleanup();
            }
        }
        
        private void sendEncryptedFile(String fname, PrintWriter w, VPNProtocol proto) throws Exception {
            File f = new File("shared/" + fname);
            if (!f.exists()) {
                w.println(VPNEncryption.encrypt("FILE_NOT_FOUND", sessionKey));
                return;
            }
            
            w.println(VPNEncryption.encrypt("FILE_START", sessionKey));
            try (BufferedReader fr = new BufferedReader(new FileReader(f))) {
                String ln;
                while ((ln = fr.readLine()) != null) {
                    if (proto instanceof CustomVPN) ln = ((CustomVPN)proto).obf(ln);
                    String encryptedLine = VPNEncryption.encrypt(ln, sessionKey);
                    w.println(encryptedLine);
                }
            }
            w.println(VPNEncryption.encrypt("FILE_END", sessionKey));
            log("Sent encrypted " + fname);
        }
        
        private void receiveEncryptedFile(String filename, BufferedReader r, PrintWriter w, VPNProtocol proto) throws Exception {
            // Send ready signal to client
            w.println(VPNEncryption.encrypt("UPLOAD_READY", sessionKey));
            log("Upload initiated for " + filename + " from " + username);
            
            // Create user directory if it doesn't exist
            File userDir = new File("shared/uploads/" + username);
            if (!userDir.exists()) {
                userDir.mkdirs();
                log("Created upload directory for " + username);
            }
            
            // Create the file
            File outFile = new File(userDir, filename);
            try (BufferedWriter fw = new BufferedWriter(new FileWriter(outFile))) {
                String encryptedLine;
                while (true) {
                    encryptedLine = r.readLine();
                    if (encryptedLine == null) break;
                    
                    String decrypted = VPNEncryption.decrypt(encryptedLine, sessionKey);
                    if ("FILE_END".equals(decrypted)) break;
                    
                    // If using CustomVPN, deobfuscate the content
                    String plain = (proto instanceof CustomVPN) 
                        ? ((CustomVPN)proto).deobf(decrypted) 
                        : decrypted;
                    
                    fw.write(plain);
                    fw.newLine();
                }
            }
            
            // Send confirmation to client
            String successMsg = "File uploaded successfully: " + filename;
            w.println(VPNEncryption.encrypt(successMsg, sessionKey));
            log("Upload completed: " + outFile.getAbsolutePath() + " from " + username);
        }
        
        private void cleanup() {
            ipPool.release(assigned);
            natManager.remove(assigned);
            clientSessionKeys.remove(clientIdentifier);
            try { sock.close(); } catch (IOException ignored) {}
            log("Disconnected: " + assigned);
        }
    }
}