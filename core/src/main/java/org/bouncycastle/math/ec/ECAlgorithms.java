package org.bouncycastle.math.ec;

import java.math.BigInteger;

import org.bouncycastle.math.field.FiniteField;
import org.bouncycastle.math.field.PolynomialExtensionField;

public class ECAlgorithms
{
    public static boolean isF2mCurve(ECCurve c)
    {
        FiniteField field = c.getField();
        return field.getDimension() > 1 && field.getCharacteristic().equals(ECConstants.TWO)
            && field instanceof PolynomialExtensionField;
    }

    public static boolean isFpCurve(ECCurve c)
    {
        return c.getField().getDimension() == 1;
    }

    public static ECPoint sumOfMultiplies(ECPoint[] ps, BigInteger[] ks)
    {
        if (ps == null || ks == null || ps.length != ks.length || ps.length < 1)
        {
            throw new IllegalArgumentException("point and scalar arrays should be non-null, and of equal, non-zero, length");
        }

        int count = ps.length;
        switch (count)
        {
        case 1:
            return ps[0].multiply(ks[0]);
        case 2:
            return sumOfTwoMultiplies(ps[0], ks[0], ps[1], ks[1]);
        default:
            break;
        }

        ECPoint p = ps[0];
        ECCurve c = p.getCurve();

        ECPoint[] imported = new ECPoint[count];
        imported[0] = p;
        for (int i = 1; i < count; ++i)
        {
            imported[i] = importPoint(c, ps[i]);
        }

        return implSumOfMultiplies(imported, ks);
    }

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

        return implShamirsTrickWNaf(P, a, Q, b);
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

        return implShamirsTrickJsf(P, k, Q, l);
    }

    public static ECPoint importPoint(ECCurve c, ECPoint p)
    {
        ECCurve cp = p.getCurve();
        if (!c.equals(cp))
        {
            throw new IllegalArgumentException("Point must be on the same curve");
        }
        return c.importPoint(p);
    }

    public static void montgomeryTrick(ECFieldElement[] zs, int off, int len)
    {
        /*
         * Uses the "Montgomery Trick" to invert many field elements, with only a single actual
         * field inversion. See e.g. the paper:
         * "Fast Multi-scalar Multiplication Methods on Elliptic Curves with Precomputation Strategy Using Montgomery Trick"
         * by Katsuyuki Okeya, Kouichi Sakurai.
         */

        ECFieldElement[] c = new ECFieldElement[len];
        c[0] = zs[off];

        int i = 0;
        while (++i < len)
        {
            c[i] = c[i - 1].multiply(zs[off + i]);
        }

        ECFieldElement u = c[--i].invert();

        while (i > 0)
        {
            int j = off + i--;
            ECFieldElement tmp = zs[j];
            zs[j] = c[i].multiply(u);
            u = u.multiply(tmp);
        }

        zs[off] = u;
    }

    static ECPoint implShamirsTrickJsf(ECPoint P, BigInteger k,
        ECPoint Q, BigInteger l)
    {
        ECCurve curve = P.getCurve();
        ECPoint infinity = curve.getInfinity();

        // TODO conjugate co-Z addition (ZADDC) can return both of these
        ECPoint PaddQ = P.add(Q);
        ECPoint PsubQ = P.subtract(Q);

        ECPoint[] points = new ECPoint[]{ Q, PsubQ, P, PaddQ };
        curve.normalizeAll(points);

        ECPoint[] table = new ECPoint[] {
            points[3].negate(), points[2].negate(), points[1].negate(),
            points[0].negate(), infinity, points[0],
            points[1], points[2], points[3] };

        byte[] jsf = WNafUtil.generateJSF(k, l);

        ECPoint R = infinity;

        int i = jsf.length;
        while (--i >= 0)
        {
            int jsfi = jsf[i];

            // NOTE: The shifting ensures the sign is extended correctly
            int kDigit = ((jsfi << 24) >> 28), lDigit = ((jsfi << 28) >> 28);

            int index = 4 + (kDigit * 3) + lDigit;
            R = R.twicePlus(table[index]);
        }

        return R;
    }

    static ECPoint implShamirsTrickWNaf(ECPoint P, BigInteger k,
        ECPoint Q, BigInteger l)
    {
        int widthP = Math.max(2, Math.min(16, WNafUtil.getWindowSize(k.bitLength())));
        int widthQ = Math.max(2, Math.min(16, WNafUtil.getWindowSize(l.bitLength())));

        WNafPreCompInfo infoP = WNafUtil.precompute(P, widthP, true);
        WNafPreCompInfo infoQ = WNafUtil.precompute(Q, widthQ, true);

        ECPoint[] preCompP = infoP.getPreComp();
        ECPoint[] preCompQ = infoQ.getPreComp();
        ECPoint[] preCompNegP = infoP.getPreCompNeg();
        ECPoint[] preCompNegQ = infoQ.getPreCompNeg();

        byte[] wnafP = WNafUtil.generateWindowNaf(widthP, k);
        byte[] wnafQ = WNafUtil.generateWindowNaf(widthQ, l);

        int len = Math.max(wnafP.length, wnafQ.length);

        ECCurve curve = P.getCurve();
        ECPoint infinity = curve.getInfinity();

        ECPoint R = infinity;
        int zeroes = 0;

        for (int i = len - 1; i >= 0; --i)
        {
            int wiP = i < wnafP.length ? wnafP[i] : 0;
            int wiQ = i < wnafQ.length ? wnafQ[i] : 0;

            if ((wiP | wiQ) == 0)
            {
                ++zeroes;
                continue;
            }

            ECPoint r = infinity;
            if (wiP != 0)
            {
                int nP = Math.abs(wiP);
                ECPoint[] tableP = wiP < 0 ? preCompNegP : preCompP;
                r = r.add(tableP[nP >>> 1]);
            }
            if (wiQ != 0)
            {
                int nQ = Math.abs(wiQ);
                ECPoint[] tableQ = wiQ < 0 ? preCompNegQ : preCompQ;
                r = r.add(tableQ[nQ >>> 1]);
            }

            if (zeroes > 0)
            {
                R = R.timesPow2(zeroes);
                zeroes = 0;
            }

            R = R.twicePlus(r);
        }

        if (zeroes > 0)
        {
            R = R.timesPow2(zeroes);
        }

        return R;
    }

    static ECPoint implSumOfMultiplies(ECPoint[] ps, BigInteger[] ks)
    {
        int count = ps.length;
        int[] widths = new int[count];
        WNafPreCompInfo[] infos = new WNafPreCompInfo[count];
        byte[][] wnafs = new byte[count][];

        int len = 0;
        for (int i = 0; i < count; ++i)
        {
            widths[i] = Math.max(2, Math.min(16, WNafUtil.getWindowSize(ks[i].bitLength())));
            infos[i] = WNafUtil.precompute(ps[i], widths[i], true);
            wnafs[i] = WNafUtil.generateWindowNaf(widths[i], ks[i]);
            len = Math.max(len, wnafs[i].length);
        }

        ECCurve curve = ps[0].getCurve();
        ECPoint infinity = curve.getInfinity();

        ECPoint R = infinity;
        int zeroes = 0;

        for (int i = len - 1; i >= 0; --i)
        {
            ECPoint r = infinity;

            for (int j = 0; j < count; ++j)
            {
                byte[] wnaf = wnafs[j];
                int wi = i < wnaf.length ? wnaf[i] : 0;
                if (wi != 0)
                {
                    int n = Math.abs(wi);
                    WNafPreCompInfo info = infos[j];
                    ECPoint[] table = wi < 0 ? info.getPreCompNeg() : info.getPreComp();
                    r = r.add(table[n >>> 1]);
                }
            }

            if (r == infinity)
            {
                ++zeroes;
                continue;
            }

            if (zeroes > 0)
            {
                R = R.timesPow2(zeroes);
                zeroes = 0;
            }

            R = R.twicePlus(r);
        }

        if (zeroes > 0)
        {
            R = R.timesPow2(zeroes);
        }

        return R;
    }
}
