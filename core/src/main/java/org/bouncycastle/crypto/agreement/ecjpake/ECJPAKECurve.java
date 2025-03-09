package org.bouncycastle.crypto.agreement.ecjpake;

import java.math.BigInteger;

import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

/**
 * A pre-computed elliptic curve over a prime field, in short-Weierstrass form for use during an EC J-PAKE exchange.
 * <p>
 * In general, J-PAKE can use any elliptic curve or prime order group
 * that is suitable for public key cryptography.
 * <p>
 * See {@link ECJPAKECurves} for convenient standard curves.
 * <p>
 * NIST <a href="https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-186.pdf">publishes</a>
 * many curves with different forms and levels of security.
 */
public class ECJPAKECurve
{
    private final ECCurve.AbstractFp curve;
    private final ECPoint g;

    /**
     * Constructs a new {@link ECJPAKECurve}.
     * <p>
     * In general, you should use one of the pre-approved curves from
     * {@link ECJPAKECurves}, rather than manually constructing one.
     * <p>
     * The following basic checks are performed:
     * <ul>
     * <li>q must be prime</li>
     * <li>n must be prime</li>
     * <li>The curve must not be singular i.e. the discriminant is equal to 0 mod q</li>
     * <li>G must lie on the curve</li>
     * <li>n*h must equal the order of the curve</li>
     * <li>a must be in [0, q-1]</li>
     * <li>b must be in [0, q-1]</li>
     * </ul>
     * <p>
     * The prime checks are performed using {@link BigInteger#isProbablePrime(int)},
     * and are therefore subject to the same probability guarantees.
     * <p>
     * These checks prevent trivial mistakes.
     * However, due to the small uncertainties if p and q are not prime,
     * advanced attacks are not prevented.
     * Use it at your own risk.
     *
     * @throws NullPointerException     if any argument is null
     * @throws IllegalArgumentException if any of the above validations fail
     */
    public ECJPAKECurve(BigInteger q, BigInteger a, BigInteger b, BigInteger n, BigInteger h, BigInteger g_x, BigInteger g_y)
    {
        ECJPAKEUtil.validateNotNull(a, "a");
        ECJPAKEUtil.validateNotNull(b, "b");
        ECJPAKEUtil.validateNotNull(q, "q");
        ECJPAKEUtil.validateNotNull(n, "n");
        ECJPAKEUtil.validateNotNull(h, "h");
        ECJPAKEUtil.validateNotNull(g_x, "g_x");
        ECJPAKEUtil.validateNotNull(g_y, "g_y");

        /*
         * Don't skip the checks on user-specified groups.
         */
        
        /*
         * Note that these checks do not guarantee that n and q are prime.
         * We just have reasonable certainty that they are prime.
         */
        if (!q.isProbablePrime(20))
        {
            throw new IllegalArgumentException("Field size q must be prime");
        }

        if (a.compareTo(BigInteger.ZERO) < 0 || a.compareTo(q) >= 0)
        {
            throw new IllegalArgumentException("The parameter 'a' is not in the field [0, q-1]");
        }

        if (b.compareTo(BigInteger.ZERO) < 0 || b.compareTo(q) >= 0)
        {
            throw new IllegalArgumentException("The parameter 'b' is not in the field [0, q-1]");
        }

        BigInteger d = calculateDeterminant(q, a, b);
        if (d.equals(BigInteger.ZERO))
        {
            throw new IllegalArgumentException("The curve is singular, i.e the discriminant is equal to 0 mod q.");
        }

        if (!n.isProbablePrime(20))
        {
            throw new IllegalArgumentException("The order n must be prime");
        }

        /*
         * TODO It's expensive to calculate the actual total number of points. Probably the best that could be done is
         * checking that the point count is within the Hasse bound?
         */
//        BigInteger totalPoints = n.multiply(h);

        ECCurve.Fp curve = new ECCurve.Fp(q, a, b, n, h);
        ECPoint g = curve.createPoint(g_x, g_y);

        if (!g.isValid())
        {
            throw new IllegalArgumentException("The base point G does not lie on the curve.");
        }

        this.curve = curve;
        this.g = g;
    }

    /**
     * Internal package-private constructor used by the pre-approved
     * groups in {@link ECJPAKECurves}.
     * These pre-approved curves can avoid the expensive checks.
     */
    ECJPAKECurve(ECCurve.AbstractFp curve, ECPoint g)
    {
        ECJPAKEUtil.validateNotNull(curve, "curve");
        ECJPAKEUtil.validateNotNull(g, "g");
        ECJPAKEUtil.validateNotNull(curve.getOrder(), "n");
        ECJPAKEUtil.validateNotNull(curve.getCofactor(), "h");

        this.curve = curve;
        this.g = g;
    }

    public ECCurve.AbstractFp getCurve()
    {
        return curve;
    }

    public ECPoint getG()
    {
        return g;
    }

    public BigInteger getA()
    {
        return curve.getA().toBigInteger();
    }

    public BigInteger getB()
    {
        return curve.getB().toBigInteger();
    }

    public BigInteger getN()
    {
        return curve.getOrder();
    }

    public BigInteger getH()
    {
        return curve.getCofactor();
    }

    public BigInteger getQ()
    {
        return curve.getQ();
    }

    private static BigInteger calculateDeterminant(BigInteger q, BigInteger a, BigInteger b)
    {
        BigInteger a3x4 = a.multiply(a).mod(q).multiply(a).mod(q).shiftLeft(2);
        BigInteger b2x27 = b.multiply(b).mod(q).multiply(BigInteger.valueOf(27));
        return a3x4.add(b2x27).mod(q);
    }
}
