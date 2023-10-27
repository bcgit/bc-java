package org.bouncycastle.tls.injection.kems;

import org.openquantumsafe.Pair;

/**
 * A KEM (key encapsulation mechanism) is a set of functions that can be used to obtain
 * a symmetric encryption key from asymmetric keys.
 * The term KEM is a generalisation of Diffie-Hellman key exchange.
 * <p>
 * The three KEM functions actually define a half-KEM: keyGen() and decapsulate() are called at one side (e.g., the client),
 * while encapsulate() is called at the other side (e.g., the server).
 * <p>
 * This interface defines the three functions that are present in any KEM.
 * All keys/secrets/ciphertexts are byte[]-encoded.
 * #pqc-tls #injection
 *
 * @author Sergejs Kozlovics
 */
public interface KEM {
    /**
     * Generates a new key pair (pk, sk).
     *
     * @return a public key pk and its corresponding private key (=secret key) sk
     */
    Pair<byte[], byte[]> keyGen() throws Exception;

    /**
     * Generates a secret (=symmetric key K) and encapsulates it to be sent to the partner.
     *
     * @param partnerPublicKey partner's public key received during the TLS handshake
     * @return a generated symmetric key K and a ciphertext ct (=K encrypted with partner's public Key)
     */
    Pair<byte[], byte[]> encapsulate(byte[] partnerPublicKey) throws Exception;

    /**
     * Decapsulates the ciphertext (=secret K encrypted with our public key) received from the partner.
     *
     * @param secretKey  our secret key to use to decrypt the ciphertext
     * @param ciphertext the ciphertext
     * @return the shared secret K
     */
    byte[] decapsulate(byte[] secretKey, byte[] ciphertext) throws Exception;
}
