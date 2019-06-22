package org.bouncycastle.math.ec;

public class ScaleYNegateXPointMap implements ECPointMap
{
    protected final ECFieldElement scale;

    public ScaleYNegateXPointMap(ECFieldElement scale)
    {
        this.scale = scale;
    }

    public ECPoint map(ECPoint p)
    {
        return p.scaleYNegateX(scale);
    }
}
