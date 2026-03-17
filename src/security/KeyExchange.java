package security;

import javax.crypto.KeyAgreement;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;

/**
 * KeyExchange: Implementerer Diffie-Hellman for sikker nøkkelutveksling.
 * Lar to parter generere en felles hemmelighet over en usikker linje.
 */
public class KeyExchange {
    private PrivateKey privateKey;
    private byte[] publicKeyEncoded;

    public KeyExchange() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC"); // Elliptic Curve
        kpg.initialize(256);
        KeyPair kp = kpg.generateKeyPair();
        this.privateKey = kp.getPrivate();
        this.publicKeyEncoded = kp.getPublic().getEncoded();
    }

    public byte[] getPublicKeyEncoded() {
        return publicKeyEncoded;
    }

    /**
     * Beregner en felles hemmelighet basert på motpartens offentlige nøkkel.
     */
    public byte[] generateSharedSecret(byte[] receivedPubKeyBytes) throws Exception {
        KeyFactory kf = KeyFactory.getInstance("EC");
        PublicKey receivedPubKey = kf.generatePublic(new X509EncodedKeySpec(receivedPubKeyBytes));

        KeyAgreement ka = KeyAgreement.getInstance("ECDH");
        ka.init(privateKey);
        ka.doPhase(receivedPubKey, true);

        // Genererer en 256-bit secret og hasher den for å få en fast lengde på nøkkelen
        byte[] sharedSecret = ka.generateSecret();
        MessageDigest hash = MessageDigest.getInstance("SHA-256");
        return hash.digest(sharedSecret);
    }
}