package org.example;

import java.math.BigInteger;

import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

/**
 * A pre-computed elliptic curve over a prime field, in short-Weierstrass form for use during an Owl exchange.
 * <p>
 * In general, Owl can use any elliptic curve or prime order group
 * that is suitable for public key cryptography.
 * <p>
 * See {@link Owl_Curves} for convenient standard curves.
 * <p>
 * NIST <a href="https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-186.pdf">publishes</a>
 * many curves with different forms and levels of security.
 */
public class Owl_Curve
{
    private final ECCurve.AbstractFp curve;
    private final ECPoint g;

    /**
     * Constructs a new {@link Owl_Curve}.
     * <p>
     * In general, you should use one of the pre-approved curves from
     * {@link Owl_Curves}, rather than manually constructing one.
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
     * @param q The prime field modulus 
     * @param a The curve coefficient a
     * @param b The curve coefficient b
     * @param n The order of the base point G
     * @param h The co-factor
     * @param g_x The x coordinate of the base point G
     * @param g_y The y coordinate of the base point G
	 * 
     * @throws NullPointerException     if any argument is null
     * @throws IllegalArgumentException if any of the above validations fail
     */
    public Owl_Curve(BigInteger q, BigInteger a, BigInteger b, BigInteger n, BigInteger h, BigInteger g_x, BigInteger g_y)
    {
        Owl_Util.validateNotNull(a, "a");
        Owl_Util.validateNotNull(b, "b");
        Owl_Util.validateNotNull(q, "q");
        Owl_Util.validateNotNull(n, "n");
        Owl_Util.validateNotNull(h, "h");
        Owl_Util.validateNotNull(g_x, "g_x");
        Owl_Util.validateNotNull(g_y, "g_y");

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
     * groups in {@link Owl_Curves}.
     * These pre-approved curves can avoid the expensive checks.
     */
    Owl_Curve(ECCurve.AbstractFp curve, ECPoint g)
    {
        Owl_Util.validateNotNull(curve, "curve");
        Owl_Util.validateNotNull(g, "g");
        Owl_Util.validateNotNull(curve.getOrder(), "n");
        Owl_Util.validateNotNull(curve.getCofactor(), "h");

        this.curve = curve;
        this.g = g;
    }

    /**
     * Get the elliptic curve
     * @return The curve
     */
    public ECCurve.AbstractFp getCurve()
    {
        return curve;
    }

    /**
     * Get the base point G
     * @return G
     */
    public ECPoint getG()
    {
        return g;
    }

    /**
     * Get the curve coefficient a
     * @return a
     */
    public BigInteger getA()
    {
        return curve.getA().toBigInteger();
    }

    /**
     * Get the curve coefficient b
     * @return b
     */
    public BigInteger getB()
    {
        return curve.getB().toBigInteger();
    }

    /**
     * Get n, the order of the base point
     * @return n
     */
    public BigInteger getN()
    {
        return curve.getOrder();
    }

    /**
     * Get the co-factor h of the curve
     * @return h
     */
    public BigInteger getH()
    {
        return curve.getCofactor();
    }

    /**
     * Get the prime field modulus q of the curve
     * @return q
     */
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