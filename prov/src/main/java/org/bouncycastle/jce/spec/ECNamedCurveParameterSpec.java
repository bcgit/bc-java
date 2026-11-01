package org.bouncycastle.jce.spec;

import java.math.BigInteger;

import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

/**
 * specification signifying that the curve parameters can also be
 * referred to by name.
 * <p>
 * If you are using JDK 1.5 you should be looking at {@link ECNamedCurveSpec}.
 */
public class ECNamedCurveParameterSpec
    extends ECParameterSpec
{
    private String  name;

    public ECNamedCurveParameterSpec(
        String      name,
        ECCurve     curve,
        ECPoint     G,
        BigInteger  n)
    {
        super(curve, G, n);

        this.name = name;
    }

    public ECNamedCurveParameterSpec(
        String      name,
        ECCurve     curve,
        ECPoint     G,
        BigInteger  n,
        BigInteger  h)
    {
        super(curve, G, n, h);

        this.name = name;
    }

    public ECNamedCurveParameterSpec(
        String      name,
        ECCurve     curve,
        ECPoint     G,
        BigInteger  n,
        BigInteger  h,
        byte[]      seed)
    {
        super(curve, G, n, h, seed);

        this.name = name;
    }

    /**
     * return the name of the curve the EC domain parameters belong to.
     */
    public String getName()
    {
        return name;
    }

    /**
     * Return the curve name and its OID, for example "brainpoolP256r1 (1.3.36.3.3.2.8.1.1.7)", or a
     * description of the curve if there is no name.
     */
    public String toString()
    {
        String desc = ECUtil.namedCurveToString(name);

        return (desc != null) ? desc : super.toString();
    }
}
