package org.bouncycastle.crypto.params;

import javax.security.auth.Destroyable;

import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.sm9.SM9G2Point;
import org.bouncycastle.math.ec.sm9.SM9Pairing;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Properties;

/**
 * A user's SM9 encryption private key de = [t2]P2, a point of G2
 * (GM/T 0044.4-2016). Carries the master public key and the user's identity,
 * both needed to decapsulate/decrypt (the identity is part of the KDF input),
 * and the hid the KGC derived the key under, which the key exchange relies on
 * to form the peer's Q point.
 * <p>
 * A key additionally records which usage it was derived for - KEM/decryption
 * ({@link SM9EncMasterPrivateKeyParameters#generateUserKey(byte[], byte)}), which can be
 * declared further for one of the two (see below), or key exchange
 * ({@link SM9EncMasterPrivateKeyParameters#generateExchangeKey(byte[])})
 * - and the consumers enforce it: the key exchange evaluates the pairing
 * e(R, de) on a <b>peer-supplied</b> point R, so a key that also decapsulates
 * would hand any exchange peer the very pairing oracle on de that the KEM's
 * security argument assumes is unavailable. Keeping the two usages on separate
 * keys (distinct hid, or distinct master keys as the GM/T 0044.5 examples do)
 * is what makes sharing the master key sound.
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
 * <p>
 * <b>Usage warning:</b> one identity's key should be used for the KEM or for public-key
 * encryption, but not for both. A deployment needing both has its KGC publish a separate hid for
 * each function. A KEM / decryption key can be declared for one of the two when it is derived or
 * imported ({@link SM9EncMasterPrivateKeyParameters#generateUserKey(byte[], byte, int)},
 * {@link #fromEncoded(byte[], SM9EncMasterPublicKeyParameters, byte[], byte, int)}), and is then
 * refused for the other on every use, its first included. One declared for neither is held to the
 * first of the two it is used for, and refused for the other - see {@link #recordUsage(int)}.
 */
public class SM9EncPrivateKeyParameters
    extends AsymmetricKeyParameter
    implements Destroyable
{
    /**
     * The usage of a KEM / decryption key declared for neither of the two when it was derived or
     * imported: it is held to the first of them it is used for - see
     * {@link #recordUsage(int)}.
     */
    public static final int USAGE_UNSPECIFIED = 0;

    /**
     * The use of a key for KEM decapsulation (GM/T 0044.4-2016, clause 6): a usage a key can be
     * declared for, and one {@link #recordUsage(int)} checks.
     */
    public static final int USAGE_KEM = 1;

    /**
     * The use of a key for public-key decryption (GM/T 0044.4-2016, clause 7): a usage a key can be
     * declared for, and one {@link #recordUsage(int)} checks.
     */
    public static final int USAGE_DECRYPTION = 2;

    /**
     * The usage of a key-exchange key (GM/T 0044.3-2016), as
     * {@link SM9EncMasterPrivateKeyParameters#generateExchangeKey(byte[])} derives and
     * {@link #fromEncodedExchangeKey} imports one.
     */
    public static final int USAGE_KEY_EXCHANGE = 3;

    private SM9G2Point de;
    private volatile boolean destroyed;
    private final SM9EncMasterPublicKeyParameters masterPublicKey;
    private final byte[] identity;
    private final byte hid;
    private final int usage;

    // the record of the uses of this key's value, found or made the first time it is checked, and let
    // go by destroy()
    private SM9KeyUsageGuard.Record usageRecord;

    SM9EncPrivateKeyParameters(SM9G2Point de, SM9EncMasterPublicKeyParameters masterPublicKey,
                               byte[] identity, byte hid, int usage)
    {
        super(true);
        this.de = de;
        this.masterPublicKey = masterPublicKey;
        // cloned here rather than trusted to the caller: destroy() zeroes this array in place, so
        // a caller that handed over its own would find it cleared from under it. The signature
        // sibling has always cloned in its constructor; every caller here happened to clone first.
        this.identity = Arrays.clone(identity);
        this.hid = hid;
        this.usage = usage;
    }

    /**
     * The private point de. A consumer that decapsulates or decrypts with it calls
     * {@link #recordUsage(int)} first, as {@link org.bouncycastle.crypto.kems.SM9KEMExtractor} and
     * {@link org.bouncycastle.crypto.engines.SM9Engine} do when they are handed the key.
     *
     * @throws IllegalStateException if this key has been destroyed.
     */
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
        return usage == USAGE_KEY_EXCHANGE;
    }

    /**
     * The usage this key was derived or imported for: {@link #USAGE_KEY_EXCHANGE} for a
     * key-exchange key, {@link #USAGE_KEM} or {@link #USAGE_DECRYPTION} for a KEM / decryption
     * key declared for one of the two, and {@link #USAGE_UNSPECIFIED} for one declared for neither.
     */
    public int getUsage()
    {
        return usage;
    }

    /**
     * Record that this key is being handed over for {@code usage} - {@link #USAGE_KEM} or
     * {@link #USAGE_DECRYPTION} - refusing it if it may not be used for that. The KEM and
     * decryption entry points ({@link org.bouncycastle.crypto.kems.SM9KEMExtractor},
     * {@link org.bouncycastle.crypto.engines.SM9Engine} and the provider services built on them)
     * call this when they are handed the key, so the use is recorded then, before the operation
     * itself runs and whether or not it goes on to succeed. A call made only to find out whether a
     * use would be accepted records that use as well.
     * <p>
     * A key declared for one of the two when it was derived or imported is refused for the other,
     * on its first use as on every later one. Beyond that, a key is held to the first of the two
     * it is used for, and refused for the other. The key is recognised by its value - its point
     * and identity - rather than by this object, so the same key rebuilt from its encoding, or
     * derived again, is held to the same use, whatever usage that object was declared for.
     * Setting {@link Properties#SM9_ALLOW_MULTI_USE} to "true" turns this second check off, and
     * nothing is recorded while it is set; a declared usage still holds. A destroyed key is not
     * checked against the record of its value and adds nothing to it, whether it was destroyed before
     * its first use or since: it can no longer be used for either function, which the operation it is
     * handed to reports.
     * <p>
     * The record is kept in memory by the copy of this library in use, and is not kept across a
     * restart: an application that loads the library once, as most do, keeps one record for its
     * JVM, while one that loads a separate copy through each of several class loaders keeps a
     * separate record for each copy. Nor is a key remembered for as long as the process runs: its
     * record lasts while a key object of its value that has been handed over, and not destroyed
     * since, is in use, and while it is among the 1024 keys most recently handed over. A key rebuilt
     * for each use, among more than 1024 keys in use, can be forgotten between two of its uses, and
     * its next use is then taken as its first; a key declared for one of the two is refused for the
     * other however often it is rebuilt. The check therefore guards against a key being put to both
     * uses by mistake within one application; it does not replace using a separate key for each
     * function.
     *
     * @param usage the use about to be made of this key.
     * @throws IllegalArgumentException if usage is neither of the two, if this is a key-exchange
     * key, if this key was declared for the other, or if this key has been used for the other.
     */
    public void recordUsage(int usage)
    {
        if (usage != USAGE_KEM && usage != USAGE_DECRYPTION)
        {
            throw new IllegalArgumentException("usage must be USAGE_KEM or USAGE_DECRYPTION");
        }
        if (this.usage == USAGE_KEY_EXCHANGE)
        {
            throw new IllegalArgumentException("SM9 key-exchange user key cannot be used for " + usageName(usage));
        }
        if (this.usage != USAGE_UNSPECIFIED && this.usage != usage)
        {
            throw new IllegalArgumentException("SM9 encryption user key is declared for " + usageName(this.usage)
                + " and cannot be used for " + usageName(usage));
        }
        if (!SM9KeyUsageGuard.isOn())
        {
            return;
        }
        int held;
        synchronized (this)
        {
            // the lock destroy() takes, held until the use is recorded, so that a key destroyed while
            // this runs adds nothing to the record either
            if (destroyed)
            {
                // a destroyed key cannot be used for either function, which the operation it is handed
                // to reports; checked here, one destroyed after its first use would be refused for the
                // other function instead
                return;
            }
            held = SM9KeyUsageGuard.claim(usageRecord(), usage);
        }
        if (held != usage)
        {
            throw new IllegalArgumentException("SM9 encryption user key has been used for " + usageName(held)
                + " in this JVM: key-usage separation refuses it for " + usageName(usage) + " (set "
                + Properties.SM9_ALLOW_MULTI_USE + " to true to turn the check off)");
        }
    }

    // the record of the value of this key, found by the value the first time it is wanted; called
    // with the lock destroy() takes held, and only while this key is not destroyed
    private SM9KeyUsageGuard.Record usageRecord()
    {
        if (usageRecord == null)
        {
            byte[] point = de.getEncoded();
            try
            {
                usageRecord = SM9KeyUsageGuard.recordFor(point, identity);
            }
            finally
            {
                Arrays.clear(point);
            }
        }
        return usageRecord;
    }

    private static String usageName(int usage)
    {
        return (usage == USAGE_KEM) ? "KEM decapsulation" : "decryption";
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
        return fromEncoded(enc, masterPublicKey, identity, hid, USAGE_UNSPECIFIED);
    }

    /**
     * Rebuild a KEM / decryption user key from its bare point encoding, as
     * {@link #fromEncoded(byte[], SM9EncMasterPublicKeyParameters, byte[], byte)} does, declared for
     * one of the two. A key declared for {@link #USAGE_KEM} or {@link #USAGE_DECRYPTION} is refused
     * for the other on every use, its first included; {@link #USAGE_UNSPECIFIED} declares neither -
     * see {@link #recordUsage(int)}.
     *
     * @param enc the encoding {@link #getEncoded()} writes.
     * @param masterPublicKey the encryption master public key the key was derived under.
     * @param identity the identity the key was derived for.
     * @param hid the hid the KGC derived the key under.
     * @param usage {@link #USAGE_KEM}, {@link #USAGE_DECRYPTION} or {@link #USAGE_UNSPECIFIED}.
     * @return the rebuilt key.
     */
    public static SM9EncPrivateKeyParameters fromEncoded(
        byte[] enc, SM9EncMasterPublicKeyParameters masterPublicKey, byte[] identity, byte hid, int usage)
    {
        checkDeclaredUsage(usage);
        SM9SigPrivateKeyParameters.checkContext(masterPublicKey, identity);
        SM9EncMasterPrivateKeyParameters.checkEncryptionHid(hid);
        return checked(SM9G2Point.decode(enc), masterPublicKey, identity, hid, usage);
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
        return checked(SM9G2Point.decode(enc), masterPublicKey, identity, hid, USAGE_KEY_EXCHANGE);
    }

    // the usages a KEM / decryption key can be declared for when it is derived or imported
    static void checkDeclaredUsage(int usage)
    {
        if (usage != USAGE_UNSPECIFIED && usage != USAGE_KEM && usage != USAGE_DECRYPTION)
        {
            throw new IllegalArgumentException("usage must be USAGE_UNSPECIFIED, USAGE_KEM or USAGE_DECRYPTION"
                + " - a key-exchange key comes from generateExchangeKey or fromEncodedExchangeKey");
        }
    }

    // the key de is, once it is checked to be the key the KGC derives for identity and hid under
    // masterPublicKey: e([H1(ID || hid, N)]P1 + P_pub-e, de) = e(P_pub-e, P2). de is secret, and the
    // pairing starts its Miller loop from a random representative of it, as decryption's does
    private static SM9EncPrivateKeyParameters checked(SM9G2Point de, SM9EncMasterPublicKeyParameters masterPublicKey,
                                                      byte[] identity, byte hid, int usage)
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
        return new SM9EncPrivateKeyParameters(de, masterPublicKey, identity, hid, usage);
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
            // nor is the record of the value's use held for this object any longer
            usageRecord = null;
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
