package org.bouncycastle.jcajce.interfaces;

import java.security.KeyPair;

/**
 * A master private key capable of the KGC user-key extraction for an
 * identity-based encryption-family scheme: deriving a user's key pair from the
 * user's identity and the private-key generation function identifier hid the
 * KGC chose (GM/T 0044.3/0044.4-2016 for SM9, where one encryption master key
 * serves key exchange, KEM and public-key encryption).
 * <p>
 * The hid is what separates the functions a KGC offers. <b>Usage warning:</b> a key pair
 * generated here should be used for the KEM or for public-key encryption, but not for
 * both; a KGC offering both functions publishes a separate hid for each, as it does for
 * the key exchange.
 *
 * @see SM9SigUserKeyGenerator
 */
public interface SM9EncUserKeyGenerator
{
    /**
     * The encryption private-key generation function identifier hid, 0x03 - the
     * value the GM/T 0044.5-2016 Annex C/D worked examples publish for KEM and
     * public-key encryption. hid is not fixed by the standard: GM/T 0044.3-2016
     * defines it as the "identifier of the encryption private key generating
     * function, denoted by one byte", chosen and published by the KGC. These are
     * the two values the published GM/T 0044 examples use, and the defaults here.
     * <p>
     * The same value is declared on {@link SM9EncMasterPublicKey} and on the lightweight
     * {@link org.bouncycastle.crypto.params.SM9EncMasterPrivateKeyParameters#HID}, which both
     * JCA copies take their value from, so the three cannot drift apart.
     */
    byte HID = org.bouncycastle.crypto.params.SM9EncMasterPrivateKeyParameters.HID;

    /**
     * The key-exchange private-key generation function identifier hid, 0x02, as
     * published by the Chinese edition of the GM/T 0044.5-2016 Annex B worked
     * example (the official English edition of the same annex chose 0x03 - the
     * KGC's published choice governs). Taken from
     * {@link org.bouncycastle.crypto.params.SM9EncMasterPrivateKeyParameters#HID_EXCHANGE}, as
     * {@link #HID} is.
     */
    byte HID_EXCHANGE = org.bouncycastle.crypto.params.SM9EncMasterPrivateKeyParameters.HID_EXCHANGE;

    /**
     * Generate the key pair of the user identified by {@code identity} under the given
     * hid. This derivation is a KGC operation and is deterministic - the same
     * master key, identity and hid always yield the same pair.
     *
     * @param identity  the user's identity.
     * @param hid the private-key generation function identifier the KGC chose for the KEM /
     *            public-key encryption, {@code 0x03} in the published examples. It may not be
     *            {@link #HID_EXCHANGE}, which names the key exchange: an exchange key pair comes
     *            from {@code SM9EncMasterPrivateKey.generateExchangeKeyPair}. A KGC offering
     *            both the KEM and public-key encryption publishes a further value of its own
     *            for one of them, so that no identity's key serves both.
     * @return the user's key pair.
     */
    KeyPair generateUserKeyPair(byte[] identity, byte hid);
}
