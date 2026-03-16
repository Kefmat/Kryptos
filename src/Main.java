import security.SecurityProvider;
import security.KryptosServer;
import protocol.SecurePacket;
import util.KeyGeneratorUtil;
import util.KeyManager;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;

/**
 * Main-klasse for Project Kryptos.
 * Demonstrerer full livssyklus for sikkerhet: Rotasjon, Kryptering og IDS.
 */
public class Main {
    public static void main(String[] args) {
        try {
            System.out.println("==========================================");
            System.out.println("       KRYPTOS SECURE INTERFACE           ");
            System.out.println("==========================================");

            // Utfør nøkkelrotasjon ved oppstart (Best Practice)
            KeyManager.rotateKeys();

            // Last de nylig genererte nøklene
            byte[] aesKey = KeyGeneratorUtil.loadKeyFromFile("aes_key.bin");
            byte[] hmacKey = KeyGeneratorUtil.loadKeyFromFile("hmac_key.bin");

            SecurityProvider kryptos = new SecurityProvider(aesKey, hmacKey);

            // Start den sikre serveren
            KryptosServer server = new KryptosServer(5005, kryptos);
            Thread serverThread = new Thread(server);
            serverThread.start();

            Thread.sleep(500); // Vent på socket-initialisering

            // Test: Send autorisert kommando
            System.out.println("\n[CLIENT] Sender validert kommando...");
            sendEncrypted(kryptos, "CMD:SYSTEM_CHECK", 2001L);

            // Test: Simuler Replay Attack
            System.out.println("\n[ATTACK] Forsøker Replay Attack (samme nonce)...");
            sendEncrypted(kryptos, "CMD:SYSTEM_CHECK", 2001L);

        } catch (Exception e) {
            System.err.println("[FATAL ERROR] " + e.getMessage());
            e.printStackTrace();
        }
    }

    private static void sendEncrypted(SecurityProvider kryptos, String cmd, long nonce) throws Exception {
        String encrypted = kryptos.encrypt(cmd);
        String signature = kryptos.generateSignature(encrypted);
        SecurePacket packet = new SecurePacket(encrypted, signature, nonce);
        
        try (DatagramSocket socket = new DatagramSocket()) {
            byte[] buf = packet.toString().getBytes();
            InetAddress address = InetAddress.getByName("localhost");
            socket.send(new DatagramPacket(buf, buf.length, address, 5005));
        }
    }
}