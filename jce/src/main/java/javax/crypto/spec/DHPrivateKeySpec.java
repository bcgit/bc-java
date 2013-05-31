package javax.crypto.spec;

import java.math.BigInteger;
import java.security.spec.KeySpec;

/**
 * This class specifies a Diffie-Hellman private key with its associated parameters.
 *
 * @see DHPublicKeySpec
 */
public class DHPrivateKeySpec
    implements KeySpec
{
    private BigInteger  x;
    private BigInteger  p;
    private BigInteger  g;

    /**
     * Constructor that takes a private value <code>x</code>, a prime
     * modulus <code>p</code>, and a base generator <code>g</code>.
     */
    public DHPrivateKeySpec(
        BigInteger  x,
        BigInteger  p,
        BigInteger  g)
    {
        this.x = x;
        this.p = p;
        this.g = g;
    }

    /**
     * Returns the private value <code>x</code>.
     *
     * @return the private value <code>x</code>
     */
    public BigInteger getX()
    {
        return x;
    }

    /**
     * Returns the prime modulus <code>p</code>.
     *
     * @return the prime modulus <code>p</code>
     */
    public BigInteger getP()
    {
        return p;
    }

    /**
     * Returns the base generator <code>g</code>.
     * 
     * @return the base generator <code>g</code>
     */
    public BigInteger getG()
    {
        return g;
    }
}
