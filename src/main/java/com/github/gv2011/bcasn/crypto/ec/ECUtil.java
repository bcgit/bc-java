package com.github.gv2011.bcasn.crypto.ec;

import java.math.BigInteger;
import java.security.SecureRandom;

import com.github.gv2011.bcasn.math.ec.ECConstants;

class ECUtil
{
    static BigInteger generateK(BigInteger n, SecureRandom random)
    {
        int nBitLength = n.bitLength();
        BigInteger k;
        do
        {
            k = new BigInteger(nBitLength, random);
        }
        while (k.equals(ECConstants.ZERO) || (k.compareTo(n) >= 0));
        return k;
    }
}
