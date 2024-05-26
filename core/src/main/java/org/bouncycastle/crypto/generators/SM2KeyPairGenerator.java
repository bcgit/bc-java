package org.bouncycastle.crypto.generators;

import java.math.BigInteger;
import org.bouncycastle.util.BigIntegers;

public class SM2KeyPairGenerator
    extends ECKeyPairGenerator
{
    public SM2KeyPairGenerator()
    {
        super("SM2KeyGen");
    }

    protected boolean isOutOfRangeD(BigInteger d, BigInteger n)
    {
        return d.compareTo(ONE) < 0 || (d.compareTo(n.subtract(BigIntegers.TWO)) >= 0);
    }
}
