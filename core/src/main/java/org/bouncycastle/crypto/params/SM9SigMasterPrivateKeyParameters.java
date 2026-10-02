package org.bouncycastle.crypto.params;

import java.math.BigInteger;

import javax.security.auth.Destroyable;

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
     * The signature private-key generation function identifier hid, fixed to 0x01 for the SM9
     * signature algorithm by GM/T 0080-2020 8.1 and GB/T 41389-2022 6.3.1; GM/T 0044.2-2016
     * leaves it to the KGC and assigns no value.
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
        SM9KeyDerivation.checkScalarEncoding(enc);
        return new SM9SigMasterPrivateKeyParameters(new BigInteger(1, enc));
    }

    /**
     * Rebuild a signature master key and check it against the master public key its KGC
     * published. A key decoded from its scalar alone always agrees with the public key it
     * derives from that scalar, so a stale or substituted scalar - still 32 bytes, still in
     * [1, N-1] - imports as a well-formed key pair that is simply not the KGC's, and every user
     * key it then issues is a key of that wrong public key, whose signatures verify under it and
     * under no other; comparing against the published one catches the substitution when the
     * master key is decoded, rather than when a verifier holding the published key rejects a
     * signature.
     */
    public static SM9SigMasterPrivateKeyParameters fromEncoded(byte[] enc, SM9SigMasterPublicKeyParameters publicKey)
    {
        if (publicKey == null)
        {
            throw new NullPointerException("publicKey cannot be null");
        }
        SM9SigMasterPrivateKeyParameters key = fromEncoded(enc);
        if (!Arrays.areEqual(key.getPublicKeyParameters().getEncoded(), publicKey.getEncoded()))
        {
            key.destroy();
            throw new IllegalArgumentException("SM9 master private key does not match its master public key");
        }
        return key;
    }

    /**
     * Derive the signature private key for the user identified by {@code identity}
     * (GM/T 0044.2-2016, 5.3): t1 = H1(identity||hid, N) + ks; if t1 = 0 the master
     * key must be regenerated; otherwise t2 = ks*t1^-1 and ds = [t2]P1.
     */
    public SM9SigPrivateKeyParameters generateUserKey(byte[] identity)
    {
        SM9SigPrivateKeyParameters.checkContext(publicParams, identity);
        // t2 = ks * (H1(identity || hid, N) + ks)^-1 mod N, in the constant-time arithmetic the
        // encryption derivation shares
        BigInteger t2 = SM9KeyDerivation.t2(checkedKs(), identity, HID,
            "SM9 signature master key must be regenerated for this identity");
        ECPoint ds = SM9Curve.multiplySecure(SM9Curve.P1, t2).normalize();
        return new SM9SigPrivateKeyParameters(ds, publicParams, identity);
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
