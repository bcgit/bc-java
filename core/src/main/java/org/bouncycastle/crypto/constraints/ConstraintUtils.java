package org.bouncycastle.crypto.constraints;

import java.math.BigInteger;

import org.bouncycastle.math.ec.ECCurve;

public class ConstraintUtils
{
    /**
     * Return the bits of security for the passed in RSA modulus or DH/DSA group value.
     *
     * @param p a modulus or group value
     * @return the security strength in bits.
     */
    public static int bitsOfSecurityFor(BigInteger p)
    {
        return bitsOfSecurityForFF(p.bitLength());
    }

    /**
     * Return the bits of security for the passed in Elliptic Curve.
     *
     * @param curve the ECCurve of interest.
     * @return the security strength in bits.
     */
    public static int bitsOfSecurityFor(ECCurve curve)
    {
        int sBits = (curve.getFieldSize() + 1) / 2;

        return (sBits > 256) ? 256 : sBits;
    }

    public static int bitsOfSecurityForFF(int strength)
    {
        if (strength >= 2048)
        {
            return (strength >= 3072) ?
                        ((strength >= 7680) ?
                            ((strength >= 15360) ? 256
                            : 192)
                        : 128)
                   : 112;
        }

        return (strength >= 1024) ? 80 : 20;      // TODO: possibly a bit harsh...
    }
}
