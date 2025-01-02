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
    private final ECCurve.Fp curve;
    private final BigInteger a;
    private final BigInteger b;
    private final BigInteger q;
    private final BigInteger h;
    private final BigInteger n;
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
    public ECJPAKECurve(BigInteger a, BigInteger b, BigInteger q, BigInteger h, BigInteger n, ECPoint g, ECCurve.Fp curve)
    {
        /*
         * Don't skip the checks on user-specified groups.
         */
        this(a, b, q, h, n, g, curve, false);
    }

    /**
     * Internal package-private constructor used by the pre-approved
     * groups in {@link ECJPAKECurves}.
     * These pre-approved curves can avoid the expensive checks.
     */
    ECJPAKECurve(BigInteger a, BigInteger b, BigInteger q, BigInteger h, BigInteger n, ECPoint g, ECCurve.Fp curve, boolean skipChecks)
    {
        ECJPAKEUtil.validateNotNull(a, "a");
        ECJPAKEUtil.validateNotNull(b, "b");
        ECJPAKEUtil.validateNotNull(q, "q");
        ECJPAKEUtil.validateNotNull(h, "h");
        ECJPAKEUtil.validateNotNull(n, "n");
        ECJPAKEUtil.validateNotNull(g, "g");
        ECJPAKEUtil.validateNotNull(curve, "curve");

        if (!skipChecks)
        {

            /*
             * Note that these checks do not guarantee that n and q are prime.
             * We just have reasonable certainty that they are prime.
             */
            if (!q.isProbablePrime(20))
            {
                throw new IllegalArgumentException("Field size q must be prime");
            }

            if (!n.isProbablePrime(20))
            {
                throw new IllegalArgumentException("The order n must be prime");
            }

            if ((a.pow(3).multiply(BigInteger.valueOf(4)).add(b.pow(2).multiply(BigInteger.valueOf(27))).mod(q)) == BigInteger.valueOf(0))
            {
                throw new IllegalArgumentException("The curve is singular, i.e the discriminant is equal to 0 mod q.");
            }

            if (!g.isValid())
            {
                throw new IllegalArgumentException("The base point G does not lie on the curve.");
            }

            BigInteger totalPoints = n.multiply(h);
            if (!totalPoints.equals(curve.getOrder()))
            {
                throw new IllegalArgumentException("n is not equal to the order of your curve");
            }

            if (a.compareTo(BigInteger.ZERO) == -1 || a.compareTo(q.subtract(BigInteger.ONE)) == 1)
            {
                throw new IllegalArgumentException("The parameter 'a' is not in the field [0, q-1]");
            }

            if (b.compareTo(BigInteger.ZERO) == -1 || b.compareTo(q.subtract(BigInteger.ONE)) == 1)
            {
                throw new IllegalArgumentException("The parameter 'b' is not in the field [0, q-1]");
            }
        }

        this.a = a;
        this.b = b;
        this.h = h;
        this.n = n;
        this.q = q;
        this.g = g;
        this.curve = curve;
    }

    public BigInteger getA()
    {
        return a;
    }

    public BigInteger getB()
    {
        return b;
    }

    public BigInteger getN()
    {
        return n;
    }

    public BigInteger getH()
    {
        return h;
    }

    public BigInteger getQ()
    {
        return q;
    }

    public ECPoint getG()
    {
        return g;
    }

    public ECCurve.Fp getCurve()
    {
        return curve;
    }


}
