package org.bouncycastle.crypto.params;

import java.math.BigInteger;

import javax.security.auth.Destroyable;

import org.bouncycastle.crypto.generators.SM9Sm3;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.sm9.SM9Curve;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;

/**
 * SM9 signature master private key ks (GM/T 0044.2-2016). Held by the Key
 * Generation Center (KGC); derives the master public key P_pub-s = [ks]P2 and
 * users' signature private keys from their identities.
 */
public class SM9SigMasterPrivateKeyParameters
    extends AsymmetricKeyParameter
    implements Destroyable, SM9SigUserKeyParametersGenerator
{
    /**
     * The signature private-key generation function identifier hid, fixed to
     * 0x01 for the SM9 signature algorithm (GM/T 0044.2-2016, Annex A).
     */
    public static final byte HID = (byte)0x01;

    private BigInteger ks;
    private volatile boolean destroyed;
    private final SM9SigMasterPublicKeyParameters publicParams;

    public SM9SigMasterPrivateKeyParameters(BigInteger ks)
    {
        super(true);
        if (ks == null)
        {
            throw new NullPointerException("ks cannot be null");
        }
        if (ks.signum() <= 0 || ks.compareTo(SM9Curve.N) >= 0)
        {
            throw new IllegalArgumentException("ks must be in [1, N-1]");
        }
        this.ks = ks;
        this.publicParams = new SM9SigMasterPublicKeyParameters(SM9Curve.P2.multiply(ks));
    }

    public SM9SigMasterPublicKeyParameters getPublicKeyParameters()
    {
        return publicParams;
    }

    /**
     * The master private key ks as a 32-byte big-endian scalar.
     */
    public byte[] getEncoded()
    {
        return BigIntegers.asUnsignedByteArray(32, checkedKs());
    }

    public static SM9SigMasterPrivateKeyParameters fromEncoded(byte[] enc)
    {
        return new SM9SigMasterPrivateKeyParameters(new BigInteger(1, enc));
    }

    /**
     * Derive the signature private key for the user identified by {@code identity}
     * (GM/T 0044.2-2016, 5.3): t1 = H1(identity||hid, N) + ks; if t1 = 0 the master
     * key must be regenerated; otherwise t2 = ks*t1^-1 and ds = [t2]P1.
     */
    public SM9SigPrivateKeyParameters generateUserKey(byte[] identity)
    {
        BigInteger ks = checkedKs();
        BigInteger n = SM9Curve.N;
        byte[] z = Arrays.append(identity, HID);
        BigInteger t1 = SM9Sm3.h1(z, n).add(ks).mod(n);
        if (t1.signum() == 0)
        {
            throw new IllegalStateException("SM9 signature master key must be regenerated for this identity");
        }
        BigInteger t2 = ks.multiply(t1.modInverse(n)).mod(n);
        ECPoint ds = SM9Curve.multiplySecure(SM9Curve.P1, t2).normalize();
        return new SM9SigPrivateKeyParameters(ds, publicParams);
    }

    /**
     * Destroy this object, dropping its reference to the master secret ks.
     * <p>
     * As {@link BigInteger} is immutable the secret value cannot be zeroized in place;
     * destruction drops the reference and marks the key destroyed, after which
     * {@link #getEncoded()} and {@link #generateUserKey(byte[])} throw
     * {@link IllegalStateException}. The public key parameters remain available.
     */
    public synchronized void destroy()
    {
        if (!destroyed)
        {
            destroyed = true;
            ks = null;
        }
    }

    public boolean isDestroyed()
    {
        return destroyed;
    }

    private BigInteger checkedKs()
    {
        // the null check catches a destroy() in progress whose flag write is not yet visible;
        // as BigInteger is immutable a non-null snapshot is always the intact pre-destroy value.
        BigInteger value = this.ks;
        if (destroyed || value == null)
        {
            throw new IllegalStateException("key destroyed");
        }
        return value;
    }
}
