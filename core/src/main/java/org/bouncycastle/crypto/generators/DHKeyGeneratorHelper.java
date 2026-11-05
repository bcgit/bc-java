package org.bouncycastle.crypto.generators;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.crypto.params.DHParameters;
import org.bouncycastle.math.ec.WNafUtil;
import org.bouncycastle.util.BigIntegers;

class DHKeyGeneratorHelper
{
    static final DHKeyGeneratorHelper INSTANCE = new DHKeyGeneratorHelper();

    private static final BigInteger ONE = BigInteger.valueOf(1);
    private static final BigInteger TWO = BigInteger.valueOf(2);

    private DHKeyGeneratorHelper()
    {
    }

    BigInteger calculatePrivate(DHParameters dhParams, SecureRandom random)
    {
        int limit = dhParams.getL();

        if (limit != 0)
        {
            int minWeight = limit >>> 2;

            /*
             * PKCS#3 sec. 7.1: 2^(l-1) <= x < 2^l, and 0 < x < p - 1. Below the length of p an l-bit x is always
             * below p - 1; at the length of p it may not be, so x is drawn from [2^(l-1), p - 2] instead.
             */
            if (limit == dhParams.getP().bitLength())
            {
                BigInteger min = ONE.shiftLeft(limit - 1);
                BigInteger max = dhParams.getP().subtract(TWO);
                for (;;)
                {
                    BigInteger x = BigIntegers.createRandomInRange(min, max, random);
                    if (WNafUtil.getNafWeight(x) >= minWeight)
                    {
                        return x;
                    }
                }
            }

            for (;;)
            {
                BigInteger x = BigIntegers.createRandomBigInteger(limit, random).setBit(limit - 1);
                if (WNafUtil.getNafWeight(x) >= minWeight)
                {
                    return x;
                }
            }
        }

        BigInteger min = TWO;
        int m = dhParams.getM();
        if (m != 0)
        {
            min = ONE.shiftLeft(m - 1);
        }

        BigInteger q = dhParams.getQ();
        if (q == null)
        {
            q = dhParams.getP();
        }
        BigInteger max = q.subtract(TWO);

        int minWeight = max.bitLength() >>> 2;
        for (;;)
        {
            BigInteger x = BigIntegers.createRandomInRange(min, max, random);
            if (WNafUtil.getNafWeight(x) >= minWeight)
            {
                return x;
            }
        }
    }

    BigInteger calculatePublic(DHParameters dhParams, BigInteger x)
    {
        return dhParams.getG().modPow(x, dhParams.getP());
    }
}
