package org.bouncycastle.crypto.params;

import java.math.BigInteger;

import org.bouncycastle.crypto.digests.SM9Sm3;
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
{
    /**
     * The encryption private-key generation function identifier hid, fixed to
     * 0x03 for SM9 (GM/T 0044.4-2016, Annex C/D).
     */
    public static final byte HID = (byte)0x03;

    /**
     * The key-exchange private-key generation function identifier hid, 0x02
     * (GM/T 0044.3-2016). Key exchange reuses the encryption master key with
     * this hid.
     */
    public static final byte HID_EXCHANGE = (byte)0x02;

    private final BigInteger ke;
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

    BigInteger getKe()
    {
        return ke;
    }

    /**
     * The master private key ke as a 32-byte big-endian scalar.
     */
    public byte[] getEncoded()
    {
        return BigIntegers.asUnsignedByteArray(32, ke);
    }

    public static SM9EncMasterPrivateKeyParameters fromEncoded(byte[] enc)
    {
        return new SM9EncMasterPrivateKeyParameters(new BigInteger(1, enc));
    }

    /**
     * Derive the encryption private key de = [t2]P2 (a G2 point) for the user
     * identified by {@code id} (GM/T 0044.4-2016): t1 = H1(id||hid, N) + ke;
     * if t1 = 0 the master key must be regenerated; otherwise t2 = ke*t1^-1.
     */
    public SM9EncPrivateKeyParameters generatePrivateKey(byte[] id)
    {
        return generatePrivateKey(id, HID);
    }

    /**
     * Derive a private key with an explicit hid (0x03 for encryption/KEM, 0x02
     * for key exchange).
     */
    public SM9EncPrivateKeyParameters generatePrivateKey(byte[] id, byte hid)
    {
        BigInteger n = SM9Curve.N;
        BigInteger t1 = SM9Sm3.h1(Arrays.append(id, hid), n).add(ke).mod(n);
        if (t1.signum() == 0)
        {
            throw new IllegalStateException("SM9 encryption master key must be regenerated for this identity");
        }
        BigInteger t2 = ke.multiply(t1.modInverse(n)).mod(n);
        SM9G2Point de = SM9Curve.P2.multiply(t2);
        return new SM9EncPrivateKeyParameters(de, publicParams, Arrays.clone(id));
    }
}
