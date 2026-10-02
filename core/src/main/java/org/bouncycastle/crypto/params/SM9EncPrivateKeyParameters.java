package org.bouncycastle.crypto.params;

import javax.security.auth.Destroyable;

import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.sm9.SM9G2Point;
import org.bouncycastle.math.ec.sm9.SM9Pairing;
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
 * <p>
 * The usage a key records separates the key exchange from KEM / decryption; it does not
 * separate the KEM from public-key encryption. <b>Usage warning:</b> one identity's key
 * should be used for the KEM or for public-key encryption, but not for both. A deployment
 * needing both has its KGC publish a separate hid for each function, which is not
 * something this class can apply.
 * <p>
 * A key rebuilt from its encoding ({@link #fromEncoded} /
 * {@link #fromEncodedExchangeKey}) carries the usage the importer names - the
 * point encoding itself does not record which usage the KGC derived it for -
 * so an importer must claim the usage the key was actually derived under. The
 * rest of what it carries is checked: the point is refused unless it is the key
 * the KGC derives for the identity and hid under the master public key it is
 * imported with. Where the KGC derives an identity's exchange key and its KEM /
 * decryption key under one hid, the two are the same point, and the usage is the
 * one thing that check cannot tell.
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
        // cloned here rather than trusted to the caller: destroy() zeroes this array in place, so
        // a caller that handed over its own would find it cleared from under it. The signature
        // sibling has always cloned in its constructor; every caller here happened to clone first.
        this.identity = Arrays.clone(identity);
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

    /**
     * The identity this key was derived for. Synchronized with {@link #destroy()}, which zeroes
     * the array in place: the flag is set before the clear, but reading a byte the clear has
     * already written does not order the reader after the flag, so an unsynchronized copy could
     * return a partly zeroed identity with the flag still reading false.
     */
    public synchronized byte[] getIdentity()
    {
        if (destroyed)
        {
            throw new IllegalStateException("key destroyed");
        }
        return Arrays.clone(identity);
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
     * Rebuild a KEM / decryption user key from its bare point encoding. For a key
     * the KGC derived for the key exchange use {@link #fromEncodedExchangeKey}
     * instead - the usage is the importer's claim (see the class note), and the
     * consumers enforce whichever is claimed.
     * <p>
     * The hid is the KGC's published choice and may be any one byte except
     * {@link SM9EncMasterPrivateKeyParameters#HID_EXCHANGE}, as where the key is
     * derived: a point formed under
     * {@link SM9EncMasterPrivateKeyParameters#HID_EXCHANGE} is that identity's
     * exchange key, so claiming the KEM / decryption usage for it here is the one
     * combination of usage and hid that names two different keys at once. The claim
     * is checked against the hid rather than left to stand alone.
     * <p>
     * The point itself is checked against the master public key, identity and hid, by
     * the KGC's own relation e([H1(ID || hid, N)]P1 + P_pub-e, de) = e(P_pub-e, P2),
     * which holds exactly when de = [ke * (H1(ID || hid, N) + ke)^-1]P2 for the ke
     * behind that P_pub-e. The encoding is the point alone, and the other three arrive
     * beside it: a point paired with another master public key, or filed under another
     * identity or hid, is refused with an {@link IllegalArgumentException} rather than
     * imported as a key it is not. The check costs a pairing, several times what
     * decoding the point costs, G2 subgroup check included, and on a master public
     * key's first use a second, e(P_pub-e, P2), which the master public key then keeps.
     */
    public static SM9EncPrivateKeyParameters fromEncoded(
        byte[] enc, SM9EncMasterPublicKeyParameters masterPublicKey, byte[] identity, byte hid)
    {
        SM9SigPrivateKeyParameters.checkContext(masterPublicKey, identity);
        SM9EncMasterPrivateKeyParameters.checkEncryptionHid(hid);
        return checked(SM9G2Point.decode(enc), masterPublicKey, identity, hid, false);
    }

    /**
     * Rebuild a key-exchange user key from its bare point encoding, under
     * {@link SM9EncMasterPrivateKeyParameters#HID_EXCHANGE} - the import path for
     * an exchange party that received its key from the KGC rather than deriving
     * it in-process via
     * {@link SM9EncMasterPrivateKeyParameters#generateExchangeKey(byte[])}. The
     * point is checked as {@link #fromEncoded} checks it.
     */
    public static SM9EncPrivateKeyParameters fromEncodedExchangeKey(
        byte[] enc, SM9EncMasterPublicKeyParameters masterPublicKey, byte[] identity)
    {
        return fromEncodedExchangeKey(enc, masterPublicKey, identity, SM9EncMasterPrivateKeyParameters.HID_EXCHANGE);
    }

    /**
     * Rebuild a key-exchange user key from its bare point encoding under an
     * explicit hid, for a KGC whose published exchange hid is not
     * {@link SM9EncMasterPrivateKeyParameters#HID_EXCHANGE} (the official English
     * edition's GM/T 0044.5 Annex B example runs the exchange under 0x03). The point
     * is checked as {@link #fromEncoded} checks it.
     */
    public static SM9EncPrivateKeyParameters fromEncodedExchangeKey(
        byte[] enc, SM9EncMasterPublicKeyParameters masterPublicKey, byte[] identity, byte hid)
    {
        SM9SigPrivateKeyParameters.checkContext(masterPublicKey, identity);
        return checked(SM9G2Point.decode(enc), masterPublicKey, identity, hid, true);
    }

    // the key de is, once it is checked to be the key the KGC derives for identity and hid under
    // masterPublicKey: e([H1(ID || hid, N)]P1 + P_pub-e, de) = e(P_pub-e, P2). de is secret, and the
    // pairing starts its Miller loop from a random representative of it, as decryption's does
    private static SM9EncPrivateKeyParameters checked(SM9G2Point de, SM9EncMasterPublicKeyParameters masterPublicKey,
                                                      byte[] identity, byte hid, boolean exchangeKey)
    {
        ECPoint q;
        try
        {
            q = masterPublicKey.recipientPoint(identity, hid);
        }
        catch (IllegalArgumentException e)
        {
            // Q at infinity: the identity no user key can be derived for under this master key and
            // hid, so no point is its key
            q = null;
        }
        if (q == null || !SM9Pairing.pairing(q, de).equals(masterPublicKey.pairingWithP2()))
        {
            throw new IllegalArgumentException(
                "SM9 encryption private key does not match its master public key, identity and hid");
        }
        return new SM9EncPrivateKeyParameters(de, masterPublicKey, identity, hid, exchangeKey);
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
