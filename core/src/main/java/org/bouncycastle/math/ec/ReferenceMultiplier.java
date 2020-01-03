package org.bouncycastle.math.ec;

import java.math.BigInteger;

/**
 * @deprecated Will be removed
 */
public class ReferenceMultiplier extends AbstractECMultiplier
{
    protected ECPoint multiplyPositive(ECPoint p, BigInteger k)
    {
        return ECAlgorithms.referenceMultiply(p, k);
    }
}
