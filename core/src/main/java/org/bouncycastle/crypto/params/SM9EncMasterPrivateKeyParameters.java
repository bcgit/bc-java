package org.bouncycastle.crypto.params;

import java.math.BigInteger;

import javax.security.auth.Destroyable;

import org.bouncycastle.crypto.generators.SM9Sm3;
import org.bouncycastle.math.ec.sm9.SM9Curve;
import org.bouncycastle.math.ec.sm9.SM9G2Point;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;

/**
 * SM9 encryption master private key ke (GM/T 0044.4-2016). Held by the KGC;
 * derives the master public key P_pub-e = [ke]P1 and users' encryption private
 * keys de = [t2]P2 from their identities.
 */
public class SM9EncMasterPrivateKeyParameters
    extends AsymmetricKeyParameter
    implements Destroyable, SM9EncUserKeyParametersGenerator
{
    /**
     * The encryption private-key generation function identifier hid, 0x03 - the
     * value used by the GM/T 0044.5-2016 Annex C/D worked examples (and, note,
     * by the official English edition's Annex B key exchange example).
     * <p>
     * hid is not fixed by the standard: GM/T 0044.3-2016 defines it as the
     * "identifier of the encryption private key generating function, denoted by
     * one byte", which the KGC chooses and publishes. These constants are the
     * two identifier values the published GM/T 0044 examples use, and the only
     * values {@link #generateUserKey(byte[], byte)} accepts.
     */
    public static final byte HID = (byte)0x03;

    /**
     * The key-exchange private-key generation function identifier hid, 0x02, as
     * used by the Chinese edition of the GM/T 0044.5-2016 Annex B worked example
     * (the official English edition of the same annex chose 0x03 - see the hid
     * note on {@link #HID}; the KGC's published choice governs).
     * <p>
     * Key exchange runs on the encryption master key: a single master key may
     * serve both key exchange and KEM / public-key encryption. That sharing is
     * the design of GM/T 0044, not a caller-side shortcut - GM/T 0044.3-2016 6.1
     * names the protocol's own inputs as the encryption public key P_pub-e and
     * the encryption private key de. The hid is folded into the derivation
     * (t1 = H1(identity || hid, N) + ke, see {@link #generateUserKey(byte[], byte)}),
     * so when the KGC publishes distinct hids for the two functions the user
     * keys obtained under them are as independent as keys for two different
     * identities. If the two collide on one master key, a user's exchange key
     * and decryption key are the identical G2 point - and since the exchange
     * pairs that point with a peer-supplied value, any peer would gain the
     * pairing oracle on de that the KEM's security argument assumes away. The
     * API therefore derives the two usages as distinct key objects
     * ({@link #generateUserKey(byte[], byte)} vs
     * {@link #generateExchangeKey(byte[])}) which the consumers mutually
     * reject; a KGC whose lifecycles differ should prefer separate master keys
     * outright, as the GM/T 0044.5 worked examples themselves do.
     */
    public static final byte HID_EXCHANGE = (byte)0x02;

    private BigInteger ke;
    private volatile boolean destroyed;
    private final SM9EncMasterPublicKeyParameters publicParams;

    public SM9EncMasterPrivateKeyParameters(BigInteger ke)
    {
        super(true);
        if (ke == null)
        {
            throw new NullPointerException("ke cannot be null");
        }
        if (ke.signum() <= 0 || ke.compareTo(SM9Curve.N) >= 0)
        {
            throw new IllegalArgumentException("ke must be in [1, N-1]");
        }
        this.ke = ke;
        this.publicParams = new SM9EncMasterPublicKeyParameters(SM9Curve.multiplySecure(SM9Curve.P1, ke).normalize());
    }

    public SM9EncMasterPublicKeyParameters getPublicKeyParameters()
    {
        return publicParams;
    }

    /**
     * The master private key ke as a 32-byte big-endian scalar.
     */
    public byte[] getEncoded()
    {
        return BigIntegers.asUnsignedByteArray(32, checkedKe());
    }

    public static SM9EncMasterPrivateKeyParameters fromEncoded(byte[] enc)
    {
        return new SM9EncMasterPrivateKeyParameters(new BigInteger(1, enc));
    }

    /**
     * Derive the KEM / decryption private key de = [t2]P2 (a G2 point) for the
     * user identified by {@code identity} under the given hid (GM/T 0044.4-2016):
     * t1 = H1(identity||hid, N) + ke; if t1 = 0 the master key must be regenerated;
     * otherwise t2 = ke*t1^-1. The derived key records the hid it was formed
     * under. For a key-exchange user key use
     * {@link #generateExchangeKey(byte[])} - the two usages are kept on
     * separate keys and the consumers enforce it.
     */
    public SM9EncPrivateKeyParameters generateUserKey(byte[] identity, byte hid)
    {
        return generateKey(identity, hid, false);
    }

    /**
     * Derive the key-exchange private key of the user identified by {@code identity}
     * (GM/T 0044.3-2016), under {@link #HID_EXCHANGE} - the hid the standard's
     * Chinese-edition worked example publishes for the exchange.
     */
    public SM9EncPrivateKeyParameters generateExchangeKey(byte[] identity)
    {
        return generateKey(identity, HID_EXCHANGE, true);
    }

    /**
     * Derive the key-exchange private key of the user identified by {@code identity}
     * under an explicit hid, for a KGC whose published exchange hid is not
     * {@link #HID_EXCHANGE} (the official English edition's Annex B example
     * runs the exchange under 0x03, on its own master key).
     */
    public SM9EncPrivateKeyParameters generateExchangeKey(byte[] identity, byte hid)
    {
        return generateKey(identity, hid, true);
    }

    private SM9EncPrivateKeyParameters generateKey(byte[] identity, byte hid, boolean exchangeKey)
    {
        checkHid(hid);
        BigInteger ke = checkedKe();
        BigInteger n = SM9Curve.N;
        BigInteger t1 = SM9Sm3.h1(Arrays.append(identity, hid), n).add(ke).mod(n);
        if (t1.signum() == 0)
        {
            throw new IllegalStateException("SM9 encryption master key must be regenerated for this identity");
        }
        // t1 carries the master private key ke, and BigInteger.modInverse is variable time in the
        // value it inverts, so use the constant-time inverse - N is the group order and so is odd.
        BigInteger t2 = ke.multiply(BigIntegers.modOddInverse(n, t1)).mod(n);
        SM9G2Point de = SM9Curve.P2.multiply(t2);
        return new SM9EncPrivateKeyParameters(de, publicParams, Arrays.clone(identity), hid, exchangeKey);
    }

    static void checkHid(byte hid)
    {
        if (hid != HID && hid != HID_EXCHANGE)
        {
            throw new IllegalArgumentException("hid must be HID (0x03) or HID_EXCHANGE (0x02)");
        }
    }

    /**
     * Destroy this object, dropping its reference to the master secret ke.
     * <p>
     * As {@link BigInteger} is immutable the secret value cannot be zeroized in place;
     * destruction drops the reference and marks the key destroyed, after which
     * {@link #getEncoded()} and {@link #generateUserKey(byte[], byte)} throw
     * {@link IllegalStateException}. The public key parameters remain available.
     */
    public synchronized void destroy()
    {
        if (!destroyed)
        {
            destroyed = true;
            ke = null;
        }
    }

    public boolean isDestroyed()
    {
        return destroyed;
    }

    private BigInteger checkedKe()
    {
        // the null check catches a destroy() in progress whose flag write is not yet visible;
        // as BigInteger is immutable a non-null snapshot is always the intact pre-destroy value.
        BigInteger value = this.ke;
        if (destroyed || value == null)
        {
            throw new IllegalStateException("key destroyed");
        }
        return value;
    }
}
