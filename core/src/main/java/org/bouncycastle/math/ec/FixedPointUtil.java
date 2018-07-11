package org.bouncycastle.math.ec;

import java.math.BigInteger;

public class FixedPointUtil
{
    public static final String PRECOMP_NAME = "bc_fixed_point";

    public static int getCombSize(ECCurve c)
    {
        BigInteger order = c.getOrder();
        return order == null ? c.getFieldSize() + 1 : order.bitLength(); 
    }

    public static FixedPointPreCompInfo getFixedPointPreCompInfo(PreCompInfo preCompInfo)
    {
        return (preCompInfo instanceof FixedPointPreCompInfo) ? (FixedPointPreCompInfo)preCompInfo : null;
    }

    public static FixedPointPreCompInfo precompute(final ECPoint p)
    {
        final ECCurve c = p.getCurve();

        return (FixedPointPreCompInfo)c.precompute(p, PRECOMP_NAME, new PreCompCallback()
        {
            public PreCompInfo precompute(PreCompInfo existing)
            {
                FixedPointPreCompInfo existingFP = (existing instanceof FixedPointPreCompInfo) ? (FixedPointPreCompInfo)existing : null;

                int bits = getCombSize(c);
                int minWidth = bits > 250 ? 6 : 5;
                int n = 1 << minWidth;

                if (checkExisting(existingFP, n))
                {
                    return existingFP;
                }

                int d = (bits + minWidth - 1) / minWidth;

                ECPoint[] pow2Table = new ECPoint[minWidth + 1];
                pow2Table[0] = p;
                for (int i = 1; i < minWidth; ++i)
                {
                    pow2Table[i] = pow2Table[i - 1].timesPow2(d);
                }

                // This will be the 'offset' value 
                pow2Table[minWidth] = pow2Table[0].subtract(pow2Table[1]);

                c.normalizeAll(pow2Table);

                ECPoint[] lookupTable = new ECPoint[n];
                lookupTable[0] = pow2Table[0];

                for (int bit = minWidth - 1; bit >= 0; --bit)
                {
                    ECPoint pow2 = pow2Table[bit];

                    int step = 1 << bit;
                    for (int i = step; i < n; i += (step << 1))
                    {
                        lookupTable[i] = lookupTable[i - step].add(pow2);
                    }
                }

                c.normalizeAll(lookupTable);

                FixedPointPreCompInfo result = new FixedPointPreCompInfo();
                result.setLookupTable(c.createCacheSafeLookupTable(lookupTable, 0, lookupTable.length));
                result.setOffset(pow2Table[minWidth]);
                result.setWidth(minWidth);
                return result;
            }

            private boolean checkExisting(FixedPointPreCompInfo existingFP, int n)
            {
                return existingFP != null && checkTable(existingFP.getLookupTable(), n);
            }

            private boolean checkTable(ECLookupTable table, int n)
            {
                return table != null && table.getSize() >= n;
            }
        });
    }
}
