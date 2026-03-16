import security.SecurityProvider;
import security.KryptosServer;
import security.AuditLogger;
import protocol.SecurePacket;
import util.KeyGeneratorUtil;
import util.KeyManager;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;

/**
 * Main-klasse for Project Kryptos.
 * Demonstrerer full livssyklus: Rotasjon, Kryptering, IDS og Audit Logging.
 */
public class Main {
    public static void main(String[] args) {
        try {
            AuditLogger.logEvent("SYSTEM", "BOOT", "Kryptos Security Engine starter...");

            // 1. Nøkkelhåndtering
            KeyManager.rotateKeys();
            byte[] aesKey = KeyGeneratorUtil.loadKeyFromFile("aes_key.bin");
            byte[] hmacKey = KeyGeneratorUtil.loadKeyFromFile("hmac_key.bin");
            SecurityProvider kryptos = new SecurityProvider(aesKey, hmacKey);

            // 2. Start server
            KryptosServer server = new KryptosServer(5005, kryptos);
            new Thread(server).start();
            Thread.sleep(500);

            // 3. Scenario: Lovlig bruker
            simulateTraffic(kryptos, "CMD:STATUS_REPORT", 5001L);

            // 4. Scenario: Replay Attack (vil bli logget som ALERT)
            simulateTraffic(kryptos, "CMD:STATUS_REPORT", 5001L);

            // 5. Scenario: Ugyldig signatur (vil bli logget som ALERT)
            simulateTamperedTraffic("FAKE_ENCRYPTED_DATA", "WRONG_SIGNATURE", 5002L);

            Thread.sleep(1000);
            System.out.println("\n[SYSTEM] Sjekk logs/audit.log for fullstendig sikkerhetsrapport.");

        } catch (Exception e) {
            AuditLogger.logEvent("CRITICAL", "SYSTEM_FAULT", e.getMessage());
        }
    }

    private static void simulateTraffic(SecurityProvider kryptos, String cmd, long nonce) throws Exception {
        String enc = kryptos.encrypt(cmd);
        String sig = kryptos.generateSignature(enc);
        sendRaw(new SecurePacket(enc, sig, nonce).toString());
    }

    private static void simulateTamperedTraffic(String payload, String sig, long nonce) throws Exception {
        sendRaw(nonce + "|" + sig + "|" + payload);
    }

    private static void sendRaw(String data) throws Exception {
        try (DatagramSocket socket = new DatagramSocket()) {
            byte[] buf = data.getBytes();
            InetAddress addr = InetAddress.getByName("localhost");
            socket.send(new DatagramPacket(buf, buf.length, addr, 5005));
        }
    }
}