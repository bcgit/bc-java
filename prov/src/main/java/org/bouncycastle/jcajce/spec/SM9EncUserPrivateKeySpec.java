package org.bouncycastle.jcajce.spec;

import java.security.spec.EncodedKeySpec;

import org.bouncycastle.jcajce.interfaces.SM9EncMasterPublicKey;
import org.bouncycastle.jcajce.interfaces.SM9EncUserKeyGenerator;
import org.bouncycastle.util.Arrays;

/**
 * Key spec for rebuilding a user's SM9 encryption (KEM / decryption) private key
 * (de, GM/T 0044.4) from its PKCS#8 encoding through {@code KeyFactory.SM9}. The
 * encoding alone does not determine a usable key - decryption also needs the
 * encryption master public key, the user's identity (part of the decryption KDF
 * input) and the hid the KGC derived the key under, none of which are part of it -
 * so the spec carries all four, letting a stored user key be reconstituted without
 * access to the master private key.
 * <p>
 * This extends {@link EncodedKeySpec} rather than {@link java.security.spec.PKCS8EncodedKeySpec}:
 * the encoded bytes are a real PKCS#8 encoding (reflected in {@link #getFormat()}), but the
 * spec is not self-sufficient the way a plain PKCS8EncodedKeySpec is meant to be, and
 * subclassing the concrete JDK type would let generic code treat it as one.
 * <p>
 * The matching spec is returned by the factory's {@code getKeySpec} method, so a
 * user key round-trips: store {@code getEncoded()} (or ask for this spec), rebuild
 * with {@code generatePrivate}. A key-exchange user key rebuilds the same way with
 * {@code exchangeKey} set - the encoding does not record which usage the KGC
 * derived the key for, so the flag is the importer's claim, and the consumers
 * enforce whichever usage the rebuilt key carries ({@code KeyAgreement.SM9}
 * accepts only exchange keys; the KEM and cipher only non-exchange keys).
 * <p>
 * {@code KeyFactory.SM9} checks the point against the other three, by the KGC's own
 * relation e([H1(ID || hid, N)]P1 + P_pub-e, de) = e(P_pub-e, P2), and refuses the spec
 * with an {@link java.security.spec.InvalidKeySpecException} unless the point is the key
 * the KGC derives for this identity and hid under this master public key.
 * <p>
 * The claim is not taken entirely on its own, though: the hid says which of the
 * KGC's generation functions formed the point, so the one combination that names two
 * keys at once - the KEM / decryption usage claimed for a point derived under
 * {@link org.bouncycastle.jcajce.interfaces.SM9EncUserKeyGenerator#HID_EXCHANGE} - is
 * refused where both halves are first in hand, by this spec's constructor, as well as
 * by {@code KeyFactory.SM9} behind it.
 * What the two cannot separate is a KGC that publishes one hid for both functions,
 * where the exchange key and the decryption key of an identity are the same point;
 * such a master key has to serve one function only, as the GM/T 0044.5 worked
 * examples themselves arrange.
 */
public class SM9EncUserPrivateKeySpec
    extends EncodedKeySpec
{
    private final SM9EncMasterPublicKey masterPublicKey;
    private final byte[] identity;
    private final byte hid;
    private final boolean exchangeKey;

    /**
     * Base constructor, for a KEM / decryption user key.
     *
     * @param pkcs8Encoding   the user private key's PKCS#8 encoding, as returned by
     *                        the key's {@code getEncoded()}.
     * @param masterPublicKey the encryption master public key the user key was derived under.
     * @param identity        the user's identity.
     * @param hid             the private-key generation function identifier the KGC
     *                        derived the key under - its published choice,
     *                        {@link org.bouncycastle.jcajce.interfaces.SM9EncUserKeyGenerator#HID}
     *                        in the published examples, and never
     *                        {@link org.bouncycastle.jcajce.interfaces.SM9EncUserKeyGenerator#HID_EXCHANGE},
     *                        which names the key exchange.
     */
    public SM9EncUserPrivateKeySpec(byte[] pkcs8Encoding, SM9EncMasterPublicKey masterPublicKey,
                                    byte[] identity, byte hid)
    {
        this(pkcs8Encoding, masterPublicKey, identity, hid, false);
    }

    /**
     * @param pkcs8Encoding   the user private key's PKCS#8 encoding, as returned by
     *                        the key's {@code getEncoded()}.
     * @param masterPublicKey the encryption master public key the user key was derived under.
     * @param identity        the user's identity.
     * @param hid             the private-key generation function identifier the KGC
     *                        derived the key under.
     * @param exchangeKey     whether the KGC derived the key for the key exchange
     *                        (from {@code generateExchangeKeyPair}) rather than for
     *                        KEM / decryption.
     */
    public SM9EncUserPrivateKeySpec(byte[] pkcs8Encoding, SM9EncMasterPublicKey masterPublicKey,
                                    byte[] identity, byte hid, boolean exchangeKey)
    {
        super(pkcs8Encoding);
        if (masterPublicKey == null)
        {
            throw new NullPointerException("masterPublicKey cannot be null");
        }
        if (identity == null)
        {
            throw new NullPointerException("identity cannot be null");
        }
        if (!exchangeKey && hid == SM9EncUserKeyGenerator.HID_EXCHANGE)
        {
            // the pair contradicts itself, and both halves are here: refused now rather than by
            // the KeyFactory later, perhaps in code far from wherever the spec was assembled
            throw new IllegalArgumentException(
                "hid must not be HID_EXCHANGE (0x02) for a KEM or decryption user key - that hid names the key exchange");
        }
        this.masterPublicKey = masterPublicKey;
        this.identity = Arrays.clone(identity);
        this.hid = hid;
        this.exchangeKey = exchangeKey;
    }

    public SM9EncMasterPublicKey getMasterPublicKey()
    {
        return masterPublicKey;
    }

    public byte[] getIdentity()
    {
        return Arrays.clone(identity);
    }

    /**
     * The private-key generation function identifier hid the key was derived
     * under - the KGC's published choice, not sensitive.
     */
    public byte getHid()
    {
        return hid;
    }

    /**
     * Whether the key rebuilds as a key-exchange user key rather than a KEM /
     * decryption one.
     */
    public boolean isExchangeKey()
    {
        return exchangeKey;
    }

    public String getFormat()
    {
        return "PKCS#8";
    }
}
