package security;

import util.KeyManager;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.util.HashSet;
import java.util.Set;

/**
 * KryptosServer: Sikker mottaker med FirewallEngine og Active Defense.
 */
public class KryptosServer implements Runnable {
    private int port;
    private SecurityProvider security;
    private FirewallEngine firewall;
    private boolean running = true;
    
    private Set<Long> usedNonces = new HashSet<>();

    public KryptosServer(int port, SecurityProvider security) {
        this.port = port;
        this.security = security;
        this.firewall = new FirewallEngine();
    }

    @Override
    public void run() {
        try (DatagramSocket socket = new DatagramSocket(port)) {
            AuditLogger.logEvent("INFO", "SERVER_START", "Lytter på port " + port + " med Firewall");
            byte[] buffer = new byte[2048];

            while (running) {
                DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
                socket.receive(packet);

                String sourceIp = packet.getAddress().getHostAddress();

                // 1. Brannmur-sjekk (skjer aller først)
                if (!firewall.isAllowed(sourceIp)) {
                    continue; // Dropper pakken lydløst for å spare ressurser
                }

                String rawData = new String(packet.getData(), 0, packet.getLength());
                processSecurePacket(rawData, sourceIp);
            }
        } catch (Exception e) {
            AuditLogger.logEvent("CRITICAL", "SERVER_FATAL", e.getMessage());
        }
    }

    private void processSecurePacket(String raw, String sourceIp) {
        try {
            String[] parts = raw.split("\\|");
            if (parts.length < 3) {
                firewall.registerViolation(sourceIp);
                return;
            }

            long nonce = Long.parseLong(parts[0]);
            String signature = parts[1];
            String payload = parts[2];

            // 2. Anti-Replay og Signatur
            if (usedNonces.contains(nonce) || !security.verifySignature(payload, signature)) {
                firewall.registerViolation(sourceIp);
                return;
            }

            // 3. Dekryptering
            String decrypted = security.decrypt(payload);
            usedNonces.add(nonce);
            
            AuditLogger.logEvent("INFO", "AUTHORIZED_CMD", "Fra " + sourceIp + ": " + decrypted);

        } catch (Exception e) {
            AuditLogger.logEvent("ERROR", "PROC_ERROR", sourceIp + ": " + e.getMessage());
        }
    }

    public void stop() { this.running = false; }
}