package org.bouncycastle.math.ec;

import java.math.BigInteger;

import org.bouncycastle.math.raw.Nat;

public class FixedPointCombMultiplier extends AbstractECMultiplier
{
    protected ECPoint multiplyPositive(ECPoint p, BigInteger k)
    {
        ECCurve c = p.getCurve();
        int size = FixedPointUtil.getCombSize(c);

        if (k.bitLength() > size)
        {
            /*
             * TODO The comb works best when the scalars are less than the (possibly unknown) order.
             * Still, if we want to handle larger scalars, we could allow customization of the comb
             * size, or alternatively we could deal with the 'extra' bits either by running the comb
             * multiple times as necessary, or by using an alternative multiplier as prelude.
             */
            throw new IllegalStateException("fixed-point comb doesn't support scalars larger than the curve order");
        }

        FixedPointPreCompInfo info = FixedPointUtil.precompute(p);
        ECLookupTable lookupTable = info.getLookupTable();
        int width = info.getWidth();

        int d = (size + width - 1) / width;

        ECPoint R = c.getInfinity();

        int fullComb = d * width;
        int[] K = Nat.fromBigInteger(fullComb, k);

        int top = fullComb - 1; 
        for (int i = 0; i < d; ++i)
        {
            int secretIndex = 0;

            for (int j = top - i; j >= 0; j -= d)
            {
                secretIndex <<= 1;
                secretIndex |= Nat.getBit(K, j);
            }

            ECPoint add = lookupTable.lookup(secretIndex);

            R = R.twicePlus(add);
        }

        return R.add(info.getOffset());
    }

    /** @deprecated Is no longer used; remove any overrides in subclasses. */
    protected int getWidthForCombSize(int combSize)
    {
        return combSize > 257 ? 6 : 5;
    }
}
