package org.bouncycastle.jcajce.interfaces;

import java.security.KeyPair;
import java.security.PrivateKey;

/**
 * Interface for an SM9 (GM/T 0044) encryption master private key, the KGC-held
 * root of the identity-based scheme. The one encryption master key serves KEM /
 * public-key encryption (hid = 0x03), whose user key pairs come from the
 * {@link SM9EncUserKeyGenerator} extraction method, and key exchange (hid = 0x02), whose
 * user key pairs come from {@link #generateExchangeKeyPair(byte[])} - the KGC's published
 * hid distinguishing them.
 * <p>
 * <b>Usage warning:</b> the hid separates the key exchange from the other two, not the KEM
 * from public-key encryption: an identity's key should be used for the KEM or for public-key
 * encryption, but not for both. A KGC offering both publishes a separate hid for each.
 */
public interface SM9EncMasterPrivateKey
    extends PrivateKey, SM9EncUserKeyGenerator
{
    /**
     * Generate the key-exchange key pair of the user identified by
     * {@code identity}, under hid 0x02 - the exchange identifier the GM/T 0044.5
     * Chinese-edition worked example publishes. Exchange keys and KEM/decryption
     * keys are distinct objects and the consumers mutually reject them.
     *
     * @param identity the user's identity.
     * @return the user's key-exchange key pair.
     */
    KeyPair generateExchangeKeyPair(byte[] identity);

    /**
     * Generate the key-exchange key pair of the user identified by
     * {@code identity} under an explicit hid, for a KGC whose published exchange
     * hid is not 0x02.
     *
     * @param identity the user's identity.
     * @param hid      the private-key generation function identifier the KGC chose.
     * @return the user's key-exchange key pair.
     */
    KeyPair generateExchangeKeyPair(byte[] identity, byte hid);
}
