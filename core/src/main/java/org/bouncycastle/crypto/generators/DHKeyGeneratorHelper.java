package org.bouncycastle.crypto.generators;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.crypto.constraints.ConstraintUtils;
import org.bouncycastle.crypto.params.DHParameters;
import org.bouncycastle.math.ec.WNafUtil;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.Properties;

class DHKeyGeneratorHelper
{
    static final DHKeyGeneratorHelper INSTANCE = new DHKeyGeneratorHelper();

    private static final BigInteger ONE = BigInteger.valueOf(1);
    private static final BigInteger TWO = BigInteger.valueOf(2);

    private DHKeyGeneratorHelper()
    {
    }

    /**
     * Refuse a private value length l below twice the security strength of p (SP 800-56A Rev3 sec. 5.6.1.1's 2s
     * floor), unless {@link Properties#DH_ALLOW_SHORT_PRIVATE_VALUE} is set. l may come with parameters chosen by
     * someone else, and an l-bit private value can be recovered with about 2^(l/2) work. See
     * {@link #securityStrengthFor(BigInteger)} for the strength used.
     */
    static void checkPrivateValueLength(BigInteger p, int l)
    {
        if (l != 0)
        {
            int minL = 2 * securityStrengthFor(p);
            if (l < minL && !Properties.isOverrideSet(Properties.DH_ALLOW_SHORT_PRIVATE_VALUE))
            {
                throw new IllegalArgumentException("when l value specified, it must not be less than " + minL + " for a " + p.bitLength() + " bit p");
            }
        }
    }

    /**
     * The security strength s of p, in bits. From 4096 bits up this follows the strengths SP 800-56A Rev3 Appendix D
     * assigns the safe-prime groups (152, 176 and 200 bits for 4096, 6144 and 8192-bit p, the values DHStandardGroups
     * uses for l), applied as steps to any p of at least that size, which is BC's extension of the table; otherwise,
     * and where it is higher, the SP 800-57 strength.
     */
    static int securityStrengthFor(BigInteger p)
    {
        int pBits = p.bitLength();
        int s = ConstraintUtils.bitsOfSecurityFor(p);
        int appendixD = (pBits >= 8192) ? 200 : (pBits >= 6144) ? 176 : (pBits >= 4096) ? 152 : 0;

        return Math.max(s, appendixD);
    }

    BigInteger calculatePrivate(DHParameters dhParams, SecureRandom random)
    {
        int limit = dhParams.getL();

        if (limit != 0)
        {
            int minWeight = limit >>> 2;

            /*
             * PKCS#3 sec. 7.1: when l is given, x is an l-bit integer, 2^(l-1) <= x < 2^l. At l == bitLength(p) that
             * can be at or above p - 1, which is harmless: only x mod ord(g) matters, and the values reducing below
             * 2^(l-1) are disjoint from those that do not, so a single draw still carries l - 1 bits.
             */
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

    /**
     * Generate a private value x and public value y, redrawing x while y falls outside [2, p - 2] (an x that is a
     * multiple of ord(g), or ord(g)/2). The redraw is skipped for a g itself outside [2, p - 2], where no x helps.
     *
     * @return {x, y}
     */
    BigInteger[] calculateKeyPair(DHParameters dhParams, SecureRandom random)
    {
        BigInteger p = dhParams.getP();
        BigInteger pSub2 = p.subtract(TWO);
        boolean checkY = isInRange(dhParams.getG(), pSub2);

        for (;;)
        {
            BigInteger x = calculatePrivate(dhParams, random);
            BigInteger y = calculatePublic(dhParams, x);
            if (!checkY || isInRange(y, pSub2))
            {
                return new BigInteger[]{ x, y };
            }
        }
    }

    private static boolean isInRange(BigInteger v, BigInteger pSub2)
    {
        return v.compareTo(TWO) >= 0 && v.compareTo(pSub2) <= 0;
    }

    BigInteger calculatePublic(DHParameters dhParams, BigInteger x)
    {
        return dhParams.getG().modPow(x, dhParams.getP());
    }
}
