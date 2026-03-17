import security.SecurityProvider;
import security.KryptosServer;
import security.AuditLogger;
import security.SessionManager;
import protocol.SecurePacket;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;

/**
 * Main-klasse for Project Kryptos.
 * Implementerer Seamless Rekeying ved bruk av SessionManager.
 * Fjerner behovet for manuell utløpshåndtering i applikasjonslogikken.
 */
public class Main {
    private static SessionManager sessionManager = new SessionManager(10);

    public static void main(String[] args) {
        try {
            AuditLogger.logEvent("SYSTEM", "BOOT", "Kryptos med Seamless Rekeying starter...");

            // Initialiser den aller første sesjonen
            sessionManager.renegotiate();

            // Start serveren
            // Henter den første provideren fra manageren
            KryptosServer server = new KryptosServer(5005, sessionManager.getProvider());
            new Thread(server).start();
            
            // Gi serveren tid til å binde seg til porten
            Thread.sleep(500);

            // Simulerer trafikk over en lengre periode for å trigge automatiske timeouts
            System.out.println("\n[SYSTEM] Starter trafikk-simulering (Automatisert sesjonshåndtering)...");
            
            for (int i = 1; i <= 5; i++) {
                System.out.println("\n--- Meldingssyklus " + i + " ---");
                
                // SessionManager.getProvider() sjekker automatisk om nøkkelen må byttes
                SecurityProvider currentKryptos = sessionManager.getProvider();
                
                String command = "DATA_STREAM_PACKET_" + i;
                sendSecureCommand(currentKryptos, command, 4000L + i);
                
                System.out.println("Gjeldende sesjon utløper: " + sessionManager.getExpiry());
                
                // Vi venter 4 sekunder. Etter 3 sykluser (12 sekunder) vil manageren 
                // automatisk utføre en ny handshake fordi vi satte limit til 10 sekunder.
                Thread.sleep(4000); 
            }

            System.out.println("\n[SYSTEM] Simulering ferdig. Sjekk audit.log for REKEYING-hendelser.");
            
            // Avslutter programmet etter endt simulering
            System.exit(0);

        } catch (Exception e) {
            AuditLogger.logEvent("CRITICAL", "SYSTEM_FAILURE", e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }

    /**
     * Krypterer, signerer og sender en kommando over UDP.
     */
    private static void sendSecureCommand(SecurityProvider kryptos, String cmd, long nonce) throws Exception {
        String enc = kryptos.encrypt(cmd);
        String sig = kryptos.generateSignature(enc);
        SecurePacket packet = new SecurePacket(enc, sig, nonce);
        
        try (DatagramSocket socket = new DatagramSocket()) {
            byte[] buf = packet.toString().getBytes();
            InetAddress addr = InetAddress.getByName("localhost");
            DatagramPacket dp = new DatagramPacket(buf, buf.length, addr, 5005);
            socket.send(dp);
            
            System.out.println("[CLIENT] Sendte sikret pakke: " + cmd);
        }
    }
}