package org.bouncycastle.crypto.params;

import java.math.BigInteger;

import org.bouncycastle.crypto.bls.BLS12_381G1;
import org.bouncycastle.math.raw.Nat;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;

/**
 * Private-key parameters for a BLS signature scheme. The underlying secret
 * is an integer in {@code [1, r - 1]}, where r is the suite's G1 / G2
 * subgroup order.
 * <p>
 * The secret is held as its 32-byte big-endian encoding, which the signer and
 * key generator pass to the constant-time multiplications directly; it becomes
 * a {@link BigInteger}, whose arithmetic and representation are not constant
 * time, only if {@link #getSecret()} is called or the key was built from one.
 */
public class BLSPrivateKeyParameters
    extends BLSKeyParameters
{
    private static final int[] R = Nat.fromBigInteger(256, BLS12_381G1.ORDER);

    private final byte[] sk;

    /**
     * Build the key from the secret scalar, which must be in [1, r - 1].
     *
     * @deprecated use {@link #BLSPrivateKeyParameters(BLSParameters, byte[])} with the key's 32-byte encoding.
     */
    @Deprecated
    public BLSPrivateKeyParameters(BLSParameters params, BigInteger sk)
    {
        super(true, params);
        if (sk == null || sk.signum() <= 0 || sk.compareTo(BLS12_381G1.ORDER) >= 0)
        {
            throw new IllegalArgumentException("invalid BLS secret key");
        }
        this.sk = BigIntegers.asUnsignedByteArray(32, sk);
    }

    /**
     * Build the key from its 32-byte big-endian encoding, as returned by
     * {@link #getEncoded()} or {@code BLS12_381BasicScheme.keyGenEncoded}. The
     * encoding is copied, and checked to be in [1, r - 1] without converting
     * it to a {@link BigInteger}.
     *
     * @throws IllegalArgumentException if the encoding is not 32 bytes or not in [1, r - 1].
     */
    public BLSPrivateKeyParameters(BLSParameters params, byte[] encoding)
    {
        super(true, params);
        if (encoding == null || encoding.length != 32 || !isValid(encoding))
        {
            throw new IllegalArgumentException("invalid BLS secret key");
        }
        this.sk = Arrays.clone(encoding);
    }

    // whether the 32 big-endian bytes are in [1, r - 1], every limb examined
    private static boolean isValid(byte[] b)
    {
        int[] k = new int[8];
        for (int i = 0; i < 32; ++i)
        {
            int j = 31 - i;
            k[j >>> 2] |= (b[i] & 0xFF) << ((j & 3) << 3);
        }
        int d = 0;
        for (int i = 0; i < 8; ++i)
        {
            d |= k[i];
        }
        boolean valid = (Nat.lessThan(8, k, R) & ((d | -d) >> 31)) != 0;
        Arrays.fill(k, 0);
        return valid;
    }

    /**
     * @return the BLS secret scalar, as a new {@link BigInteger}; for use with
     * the constant-time multiplications prefer {@link #getEncoded()}.
     * @deprecated use {@link #getEncoded()}, the 32-byte encoding the constant-time operations take.
     */
    @Deprecated
    public BigInteger getSecret()
    {
        return new BigInteger(1, sk);
    }

    /**
     * @return the canonical 32-byte big-endian encoding of the secret
     * scalar, matching the {@code sk_to_lebytes}/{@code os2ip} convention
     * used by draft-irtf-cfrg-bls-signature {@code KeyGen}; a copy, which the
     * caller may clear after use.
     */
    public byte[] getEncoded()
    {
        return Arrays.clone(sk);
    }
}
