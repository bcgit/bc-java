package org.bouncycastle.jcajce.provider.asymmetric.util;

import java.io.IOException;
import java.math.BigInteger;

/**
 * @deprecated No longer used
 */
public interface DSAEncoder
{
    byte[] encode(BigInteger r, BigInteger s)
        throws IOException;

    BigInteger[] decode(byte[] sig)
        throws IOException;
}
