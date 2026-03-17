import security.SecurityProvider;
import security.KryptosServer;
import security.AuditLogger;
import protocol.SecurePacket;
import util.KeyGeneratorUtil;
import util.KeyManager;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;

public class Main {
    public static void main(String[] args) {
        try {
            AuditLogger.logEvent("SYSTEM", "BOOT", "Kryptos med Firewall starter...");

            KeyManager.rotateKeys();
            byte[] aesKey = KeyGeneratorUtil.loadKeyFromFile("aes_key.bin");
            byte[] hmacKey = KeyGeneratorUtil.loadKeyFromFile("hmac_key.bin");
            SecurityProvider kryptos = new SecurityProvider(aesKey, hmacKey);

            KryptosServer server = new KryptosServer(5005, kryptos);
            new Thread(server).start();
            Thread.sleep(500);

            // Scenario: En angriper sender 3 dårlige pakker
            System.out.println("\n[ATTACK] Hacker sender ugyldige signaturer...");
            for (int i = 0; i < 4; i++) {
                sendRaw("9999|FEIL_SIG|KRYPTERT_DATA");
                Thread.sleep(100);
            }

            // Scenario: Forsøk på lovlig trafikk fra samme IP (vil bli blokkert av Firewall)
            System.out.println("\n[USER] Prøver lovlig kommando fra samme IP...");
            String enc = kryptos.encrypt("CMD:RECOVERY");
            String sig = kryptos.generateSignature(enc);
            sendRaw("8001|" + sig + "|" + enc);

            System.out.println("\n[SYSTEM] Sjekk audit.log for å se Firewall i aksjon.");

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void sendRaw(String data) throws Exception {
        try (DatagramSocket socket = new DatagramSocket()) {
            byte[] buf = data.getBytes();
            InetAddress addr = InetAddress.getByName("localhost");
            socket.send(new DatagramPacket(buf, buf.length, addr, 5005));
        }
    }
}