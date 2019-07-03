package org.bouncycastle.math.ec;

public class SimpleLookupTable
    extends AbstractECLookupTable
{
    private static ECPoint[] copy(ECPoint[] points, int off, int len)
    {
        ECPoint[] result = new ECPoint[len];
        for (int i = 0; i < len; ++i)
        {
            result[i] = points[off + i];
        }
        return result;
    }

    private final ECPoint[] points;

    public SimpleLookupTable(ECPoint[] points, int off, int len)
    {
        this.points = copy(points, off, len);
    }

    public int getSize()
    {
        return points.length;
    }

    public ECPoint lookup(int index)
    {
        throw new UnsupportedOperationException("Constant-time lookup not supported");
    }

    public ECPoint lookupVar(int index)
    {
        return points[index];
    }
}
