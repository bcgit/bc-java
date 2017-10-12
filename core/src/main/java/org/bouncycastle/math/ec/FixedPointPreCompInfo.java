package org.bouncycastle.math.ec;

/**
 * Class holding precomputation data for fixed-point multiplications.
 */
public class FixedPointPreCompInfo implements PreCompInfo
{
    protected ECPoint offset = null;

    /**
     * Array holding the precomputed <code>ECPoint</code>s used for a fixed
     * point multiplication.
     * 
     * @deprecated Will be removed
     */
    protected ECPoint[] preComp = null;

    /**
     * Lookup table for the precomputed {@link ECPoint}s used for a fixed point multiplication.
     */
    protected ECLookupTable lookupTable = null;

    /**
     * The width used for the precomputation. If a larger width precomputation
     * is already available this may be larger than was requested, so calling
     * code should refer to the actual width.
     */
    protected int width = -1;

    public ECLookupTable getLookupTable()
    {
        return lookupTable;
    }

    public void setLookupTable(ECLookupTable lookupTable)
    {
        this.lookupTable = lookupTable;
    }

    public ECPoint getOffset()
    {
        return offset;
    }

    public void setOffset(ECPoint offset)
    {
        this.offset = offset;
    }

    /** @deprecated Use {@link #getLookupTable()} instead */
    public ECPoint[] getPreComp()
    {
        return preComp;
    }

    /** @deprecated Use {@link #setLookupTable(ECLookupTable)} instead */
    public void setPreComp(ECPoint[] preComp)
    {
        this.preComp = preComp;
    }

    public int getWidth()
    {
        return width;
    }

    public void setWidth(int width)
    {
        this.width = width;
    }
}
