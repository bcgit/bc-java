package javax.crypto.spec;

import java.math.BigInteger;
import java.security.spec.KeySpec;

/**
 * This class specifies a Diffie-Hellman public key with its associated parameters.
 *
 * @see DHPrivateKeySpec
 */
public class DHPublicKeySpec
    implements KeySpec
{
    private BigInteger  y;
    private BigInteger  p;
    private BigInteger  g;

    /**
     * Constructor that takes a public value <code>y</code>, a prime
     * modulus <code>p</code>, and a base generator <code>g</code>.
     */
    public DHPublicKeySpec(
        BigInteger  y,
        BigInteger  p,
        BigInteger  g)
    {
        this.y = y;
        this.p = p;
        this.g = g;
    }

    /**
     * Returns the public value <code>y</code>.
     *
     * @return the public value <code>y</code>
     */
    public BigInteger getY()
    {
        return y;
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
