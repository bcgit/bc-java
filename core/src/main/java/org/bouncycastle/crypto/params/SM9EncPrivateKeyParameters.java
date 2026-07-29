package org.bouncycastle.crypto.params;

import javax.security.auth.Destroyable;

import org.bouncycastle.math.ec.sm9.SM9G2Point;
import org.bouncycastle.util.Arrays;

/**
 * A user's SM9 encryption private key de = [t2]P2, a point of G2
 * (GM/T 0044.4-2016). Carries the master public key and the user's identity,
 * both needed to decapsulate/decrypt (the identity is part of the KDF input),
 * and the hid the KGC derived the key under, which the key exchange relies on
 * to form the peer's Q point.
 * <p>
 * A key additionally records which usage it was derived for - KEM/decryption
 * ({@link SM9EncMasterPrivateKeyParameters#generateUserKey(byte[], byte)}) or
 * key exchange ({@link SM9EncMasterPrivateKeyParameters#generateExchangeKey(byte[])})
 * - and the consumers enforce it: the key exchange evaluates the pairing
 * e(R, de) on a <b>peer-supplied</b> point R, so a key that also decapsulates
 * would hand any exchange peer the very pairing oracle on de that the KEM's
 * security argument assumes is unavailable. Keeping the two usages on separate
 * keys (distinct hid, or distinct master keys as the GM/T 0044.5 examples do)
 * is what makes sharing the master key sound.
 */
public class SM9EncPrivateKeyParameters
    extends AsymmetricKeyParameter
    implements Destroyable
{
    private SM9G2Point de;
    private volatile boolean destroyed;
    private final SM9EncMasterPublicKeyParameters masterPublicKey;
    private final byte[] identity;
    private final byte hid;
    private final boolean exchangeKey;

    SM9EncPrivateKeyParameters(SM9G2Point de, SM9EncMasterPublicKeyParameters masterPublicKey,
                               byte[] identity, byte hid, boolean exchangeKey)
    {
        super(true);
        this.de = de;
        this.masterPublicKey = masterPublicKey;
        this.identity = identity;
        this.hid = hid;
        this.exchangeKey = exchangeKey;
    }

    public SM9G2Point getPrivatePoint()
    {
        return checkedDe();
    }

    public SM9EncMasterPublicKeyParameters getMasterPublicKey()
    {
        return masterPublicKey;
    }

    /**
     * The private-key generation function identifier hid this key was derived
     * under - the KGC's published choice, not sensitive.
     */
    public byte getHid()
    {
        return hid;
    }

    /**
     * Whether this key was derived for the key exchange
     * ({@link SM9EncMasterPrivateKeyParameters#generateExchangeKey(byte[])})
     * rather than for KEM / decryption. {@link org.bouncycastle.crypto.agreement.SM9KeyExchange}
     * accepts only exchange keys; {@link org.bouncycastle.crypto.kems.SM9KEMExtractor}
     * and SM9 decryption accept only non-exchange keys.
     */
    public boolean isExchangeKey()
    {
        return exchangeKey;
    }

    public byte[] getIdentity()
    {
        byte[] value = Arrays.clone(identity);
        if (destroyed)
        {
            throw new IllegalStateException("key destroyed");
        }
        return value;
    }

    /**
     * The user's encryption private key point de of G2 in uncompressed form
     * (0x04 || x || y, 129 bytes). The master public key, identity and hid are
     * not part of this encoding; supply them via {@link #fromEncoded} to rebuild
     * a usable key (the identity is part of the decryption KDF input, the hid
     * drives the key exchange's Q-point computation).
     */
    public byte[] getEncoded()
    {
        return checkedDe().getEncoded();
    }

    /**
     * Rebuild a KEM / decryption user key from its bare point encoding.
     */
    public static SM9EncPrivateKeyParameters fromEncoded(
        byte[] enc, SM9EncMasterPublicKeyParameters masterPublicKey, byte[] identity, byte hid)
    {
        SM9EncMasterPrivateKeyParameters.checkHid(hid);
        return new SM9EncPrivateKeyParameters(SM9G2Point.decode(enc), masterPublicKey, Arrays.clone(identity), hid, false);
    }

    /**
     * Rebuild a key-exchange user key from its bare point encoding.
     */
    public static SM9EncPrivateKeyParameters fromEncodedExchangeKey(
        byte[] enc, SM9EncMasterPublicKeyParameters masterPublicKey, byte[] identity, byte hid)
    {
        SM9EncMasterPrivateKeyParameters.checkHid(hid);
        return new SM9EncPrivateKeyParameters(SM9G2Point.decode(enc), masterPublicKey, Arrays.clone(identity), hid, true);
    }

    /**
     * Destroy this object, dropping its reference to the private point de and
     * zeroizing the identity.
     * <p>
     * As the point's coordinates are immutable they cannot be zeroized in place;
     * destruction drops the reference and marks the key destroyed, after which
     * {@link #getPrivatePoint()}, {@link #getEncoded()} and {@link #getIdentity()}
     * throw {@link IllegalStateException}. The master public key remains available.
     */
    public synchronized void destroy()
    {
        if (!destroyed)
        {
            destroyed = true;
            de = null;
            Arrays.clear(identity);
        }
    }

    public boolean isDestroyed()
    {
        return destroyed;
    }

    private SM9G2Point checkedDe()
    {
        // the null check catches a destroy() in progress whose flag write is not yet visible;
        // as the point is immutable a non-null snapshot is always the intact pre-destroy value.
        SM9G2Point value = this.de;
        if (destroyed || value == null)
        {
            throw new IllegalStateException("key destroyed");
        }
        return value;
    }
}
