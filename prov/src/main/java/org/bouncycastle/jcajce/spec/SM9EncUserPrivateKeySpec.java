package org.bouncycastle.jcajce.spec;

import java.security.spec.EncodedKeySpec;

import org.bouncycastle.crypto.params.SM9EncPrivateKeyParameters;
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
 * accepts only exchange keys; the KEM and cipher only non-exchange keys). The same
 * goes for a key declared for the KEM or for decryption: the encoding does not record
 * that either, so a key rebuilt from {@code getEncoded()} is declared for neither
 * unless the spec is built with the usage again, and is then held only to the first
 * of the two it is used for.
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
 * <p>
 * A KEM / decryption key can also be declared, through the constructor taking a usage, for one
 * of the SM9 KEM and {@code Cipher.SM9}; it is then refused for the other on every use, its first
 * included. A key rebuilt without a declaration is held to the first of the two it is used for -
 * see {@link SM9EncPrivateKeyParameters#recordUsage(int)}. The spec {@code getKeySpec} hands back
 * carries the usage the key was rebuilt with.
 */
public class SM9EncUserPrivateKeySpec
    extends EncodedKeySpec
{
    /**
     * The usage of a KEM / decryption key declared for neither of the KEM and {@code Cipher.SM9}:
     * it is held to the first of them it is used for. The value of
     * {@link SM9EncPrivateKeyParameters#USAGE_UNSPECIFIED}.
     */
    public static final int USAGE_UNSPECIFIED = SM9EncPrivateKeyParameters.USAGE_UNSPECIFIED;

    /**
     * The usage of a key declared for the SM9 KEM ({@code KeyGenerator.SM9-KEM},
     * {@code KEM.SM9-KEM}), which {@code Cipher.SM9} refuses. The value of
     * {@link SM9EncPrivateKeyParameters#USAGE_KEM}.
     */
    public static final int USAGE_KEM = SM9EncPrivateKeyParameters.USAGE_KEM;

    /**
     * The usage of a key declared for SM9 public-key decryption ({@code Cipher.SM9}), which the KEM
     * refuses. The value of
     * {@link SM9EncPrivateKeyParameters#USAGE_DECRYPTION}.
     */
    public static final int USAGE_DECRYPTION = SM9EncPrivateKeyParameters.USAGE_DECRYPTION;

    private final SM9EncMasterPublicKey masterPublicKey;
    private final byte[] identity;
    private final byte hid;
    private final int usage;

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
        this(pkcs8Encoding, masterPublicKey, identity, hid, false, USAGE_UNSPECIFIED);
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
        this(pkcs8Encoding, masterPublicKey, identity, hid, exchangeKey, USAGE_UNSPECIFIED);
    }

    /**
     * @param pkcs8Encoding   the user private key's PKCS#8 encoding, as returned by
     *                        the key's {@code getEncoded()}.
     * @param masterPublicKey the encryption master public key the user key was derived under.
     * @param identity        the user's identity.
     * @param hid             the private-key generation function identifier the KGC
     *                        derived the key under.
     * @param usage           the usage the KEM / decryption key rebuilds for: {@link #USAGE_KEM} or
     *                        {@link #USAGE_DECRYPTION} for a key declared for one of the two, which
     *                        the other then refuses on every use, or {@link #USAGE_UNSPECIFIED} for
     *                        one declared for neither. A key-exchange key is named through the
     *                        constructor taking {@code exchangeKey}, as
     *                        {@link SM9EncPrivateKeyParameters#fromEncodedExchangeKey} names one in
     *                        the light-weight API.
     */
    public SM9EncUserPrivateKeySpec(byte[] pkcs8Encoding, SM9EncMasterPublicKey masterPublicKey,
                                    byte[] identity, byte hid, int usage)
    {
        this(pkcs8Encoding, masterPublicKey, identity, hid, false, declaredUsage(usage));
    }

    // the constructor the public ones share, taking an argument list none of them takes: a key-exchange
    // key, or a KEM / decryption key declared for usage
    private SM9EncUserPrivateKeySpec(byte[] pkcs8Encoding, SM9EncMasterPublicKey masterPublicKey,
                                     byte[] identity, byte hid, boolean exchangeKey, int usage)
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
        this.usage = exchangeKey ? SM9EncPrivateKeyParameters.USAGE_KEY_EXCHANGE : usage;
    }

    // the usages a KEM / decryption key can be declared for, as SM9EncPrivateKeyParameters.fromEncoded
    // takes them
    private static int declaredUsage(int usage)
    {
        if (usage != USAGE_UNSPECIFIED && usage != USAGE_KEM && usage != USAGE_DECRYPTION)
        {
            throw new IllegalArgumentException("usage must be USAGE_UNSPECIFIED, USAGE_KEM or USAGE_DECRYPTION"
                + " - a key-exchange key is named by the constructor taking exchangeKey");
        }
        return usage;
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
        return usage == SM9EncPrivateKeyParameters.USAGE_KEY_EXCHANGE;
    }

    /**
     * The usage the key rebuilds for: {@link #USAGE_KEM} or {@link #USAGE_DECRYPTION} for a KEM /
     * decryption key declared for one of the two, {@link #USAGE_UNSPECIFIED} for one declared for
     * neither, and {@link SM9EncPrivateKeyParameters#USAGE_KEY_EXCHANGE} for a key-exchange key, which
     * {@link #isExchangeKey()} reports as well. The constructor taking a usage takes the first three.
     */
    public int getUsage()
    {
        return usage;
    }

    public String getFormat()
    {
        return "PKCS#8";
    }
}
