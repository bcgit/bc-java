package org.bouncycastle.crypto.params;

import java.math.BigInteger;

import org.bouncycastle.crypto.bls.BLS12_381G1;
import org.bouncycastle.util.BigIntegers;

/**
 * Private-key parameters for a BLS signature scheme. The underlying secret
 * is an integer in {@code [1, r - 1]}, where r is the suite's G1 / G2
 * subgroup order.
 */
public class BLSPrivateKeyParameters
    extends BLSKeyParameters
{
    private final BigInteger sk;

    public BLSPrivateKeyParameters(BLSParameters params, BigInteger sk)
    {
        super(true, params);
        if (sk == null || sk.signum() <= 0 || sk.compareTo(BLS12_381G1.ORDER) >= 0)
        {
            throw new IllegalArgumentException("invalid BLS secret key");
        }
        this.sk = sk;
    }

    /**
     * @return the BLS secret scalar.
     */
    public BigInteger getSecret()
    {
        return sk;
    }

    /**
     * @return the canonical 32-byte big-endian encoding of the secret
     * scalar, matching the {@code sk_to_lebytes}/{@code os2ip} convention
     * used by draft-irtf-cfrg-bls-signature {@code KeyGen}.
     */
    public byte[] getEncoded()
    {
        return BigIntegers.asUnsignedByteArray(32, sk);
    }
}
