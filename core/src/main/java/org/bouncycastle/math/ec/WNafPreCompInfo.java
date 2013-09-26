package org.bouncycastle.math.ec;

/**
 * Class holding precomputation data for the WNAF (Window Non-Adjacent Form)
 * algorithm.
 */
class WNafPreCompInfo implements PreCompInfo
{
    /**
     * Array holding the precomputed <code>ECPoint</code>s used for the Window
     * NAF multiplication in <code>
     * {@link org.bouncycastle.math.ec.multiplier.WNafMultiplier.multiply()
     * WNafMultiplier.multiply()}</code>.
     */
    private ECPoint[] preComp = null;
    private ECPoint[] preCompNeg = null;

    /**
     * Holds an <code>ECPoint</code> representing twice(this). Used for the
     * Window NAF multiplication in <code>
     * {@link org.bouncycastle.math.ec.multiplier.WNafMultiplier.multiply()
     * WNafMultiplier.multiply()}</code>.
     */
    private ECPoint twiceP = null;

    protected ECPoint[] getPreComp()
    {
        return preComp;
    }

    protected ECPoint[] getPreCompNeg()
    {
        return preCompNeg;
    }

    protected void setPreComp(ECPoint[] preComp)
    {
        this.preComp = preComp;
    }

    protected void setPreCompNeg(ECPoint[] preCompNeg)
    {
        this.preCompNeg = preCompNeg;
    }

    protected ECPoint getTwiceP()
    {
        return twiceP;
    }

    protected void setTwiceP(ECPoint twiceThis)
    {
        this.twiceP = twiceThis;
    }
}
