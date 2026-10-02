package org.bouncycastle.jcajce.interfaces;

import java.security.PublicKey;

/**
 * Interface for an SM9 (GM/T 0044) encryption master public key, the published
 * root of the identity-based scheme.
 * <p>
 * <b>Usage warning:</b> an identity's key should be used for the SM9 KEM or for
 * {@code Cipher.SM9}, but not for both. A sender uses the hid its KGC publishes for the
 * function it is using, and a KGC offering both publishes a separate one for each.
 */
public interface SM9EncMasterPublicKey
    extends PublicKey
{
    /**
     * The encryption private-key generation function identifier hid, 0x03 - the
     * value the GM/T 0044.5-2016 Annex C/D worked examples publish for KEM and
     * public-key encryption. hid is not fixed by the standard: GM/T 0044.3-2016
     * defines it as the "identifier of the encryption private key generating
     * function, denoted by one byte", chosen and published by the KGC. These are
     * the two values the published GM/T 0044 examples use, and the defaults here.
     * <p>
     * The same value is declared on {@link SM9EncUserKeyGenerator} and on the lightweight
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
     * Return the public key of the user identified by {@code identity}: the key a sender
     * encapsulates to. It is derived from the master public key and the identity
     * alone, so any sender holding the published master public key can construct
     * it - no certificate or KGC interaction is needed.
     * <p>
     * The key returned is always an {@link SM9EncUserPublicKey}, which gives back the identity
     * and the master public key it was formed from, and a caller may rely on the cast; the
     * declared type stays {@code PublicKey} so that code compiled against it keeps linking.
     *
     * @param identity the user's identity.
     * @return the user's public key, an {@link SM9EncUserPublicKey}.
     */
    PublicKey getUserPublicKey(byte[] identity);

    /**
     * Return the public key of the user identified by {@code identity} under an
     * explicit hid - {@code 0x03} for KEM / public-key encryption, {@code 0x02}
     * for key exchange; the KGC's published choice governs. As for
     * {@link #getUserPublicKey(byte[])}, the key returned is always an
     * {@link SM9EncUserPublicKey}.
     * <p>
     * A key under {@link #HID_EXCHANGE} names a key-exchange peer, for
     * {@code KeyAgreement.SM9}: {@code Cipher.SM9} and the SM9 KEM services refuse to encrypt
     * or encapsulate to it, since no decryption or decapsulation key can be derived under that
     * hid.
     *
     * @param identity the user's identity.
     * @param hid      the private-key generation function identifier the KGC chose.
     * @return the user's public key, an {@link SM9EncUserPublicKey}.
     */
    PublicKey getUserPublicKey(byte[] identity, byte hid);

    /**
     * Wrap a peer's key-exchange ephemeral value R, as received, for the final
     * {@code doPhase} of {@code KeyAgreement.SM9} - the encoding is the
     * standard's 64-byte x || y form returned by the first {@code doPhase} on the
     * peer's side. A value that is not a point of G1, or is the point at
     * infinity, is rejected here rather than reaching the pairing.
     *
     * @param encoded the peer's ephemeral value R, 64 bytes.
     * @return the peer's ephemeral value, to pass to {@code doPhase}.
     */
    PublicKey getExchangeEphemeral(byte[] encoded);
}
