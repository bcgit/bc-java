package org.bouncycastle.math.ec;

import java.math.BigInteger;

public class ECAlgorithms
{
    public static ECPoint sumOfTwoMultiplies(ECPoint P, BigInteger a,
        ECPoint Q, BigInteger b)
    {
        ECCurve cp = P.getCurve();
        Q = importPoint(cp, Q);

        // Point multiplication for Koblitz curves (using WTNAF) beats Shamir's trick
        if (cp instanceof ECCurve.F2m)
        {
            ECCurve.F2m f2mCurve = (ECCurve.F2m)cp;
            if (f2mCurve.isKoblitz())
            {
                return P.multiply(a).add(Q.multiply(b));
            }
        }

        return implShamirsTrick(P, a, Q, b);
    }

    /*
     * "Shamir's Trick", originally due to E. G. Straus
     * (Addition chains of vectors. American Mathematical Monthly,
     * 71(7):806-808, Aug./Sept. 1964)
     * <pre>
     * Input: The points P, Q, scalar k = (km?, ... , k1, k0)
     * and scalar l = (lm?, ... , l1, l0).
     * Output: R = k * P + l * Q.
     * 1: Z <- P + Q
     * 2: R <- O
     * 3: for i from m-1 down to 0 do
     * 4:        R <- R + R        {point doubling}
     * 5:        if (ki = 1) and (li = 0) then R <- R + P end if
     * 6:        if (ki = 0) and (li = 1) then R <- R + Q end if
     * 7:        if (ki = 1) and (li = 1) then R <- R + Z end if
     * 8: end for
     * 9: return R
     * </pre>
     */
    public static ECPoint shamirsTrick(ECPoint P, BigInteger k,
        ECPoint Q, BigInteger l)
    {
        ECCurve cp = P.getCurve();
        Q = importPoint(cp, Q);

        return implShamirsTrick(P, k, Q, l);
    }

    private static ECPoint importPoint(ECCurve c, ECPoint Q)
    {
        ECCurve cq = Q.getCurve();
        if (!c.equals(cq))
        {
            throw new IllegalArgumentException("P and Q must be on same curve");
        }
        return c.importPoint(Q);
    }

    private static ECPoint implShamirsTrick(ECPoint P, BigInteger k,
        ECPoint Q, BigInteger l)
    {
        P = P.normalize();
        Q = Q.normalize();

        ECPoint infinity = P.getCurve().getInfinity();

        // TODO conjugate co-Z addition (ZADDC) can return both of these
        ECPoint PaddQ = P.add(Q).normalize();
        ECPoint PsubQ = P.subtract(Q).normalize();

        ECPoint[] points = new ECPoint[] {
            PaddQ.negate(), P.negate(), PsubQ.negate(),
            Q.negate(), infinity, Q,
            PsubQ, P, PaddQ };

        byte[] kNaf = WNafUtil.generateNaf(k);
        byte[] lNaf = WNafUtil.generateNaf(l);

        ECPoint R = infinity;

        int i = Math.max(kNaf.length, lNaf.length);
        while (--i >= 0)
        {
            int kni = i < kNaf.length ? kNaf[i] + 1 : 1;
            int lni = i < lNaf.length ? lNaf[i] + 1 : 1;

            int index = kni * 3 + lni;
            R = R.twicePlus(points[index]);
        }

        return R;
    }
}
