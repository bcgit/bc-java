package org.bouncycastle.crypto.params;

import java.math.BigInteger;

public class RSAKeyParameters
    extends AsymmetricKeyParameter
{
    private static final BigInteger ONE = BigInteger.valueOf(1);

    private BigInteger      modulus;
    private BigInteger      exponent;

    public RSAKeyParameters(
        boolean     isPrivate,
        BigInteger  modulus,
        BigInteger  exponent)
    {
        super(isPrivate);

        if (!isPrivate)
        {
            if ((exponent.intValue() & 1) == 0)
            {
                throw new IllegalArgumentException("RSA publicExponent is even");
            }
        }

        this.modulus = validate(modulus);
        this.exponent = exponent;
    }   

    private BigInteger validate(BigInteger modulus)
    {
        if ((modulus.intValue() & 1) == 0)
        {
            throw new IllegalArgumentException("RSA modulus is even");
        }

        // the value is the product of the 132 smallest primes from 3 to 751
        if (!modulus.gcd(new BigInteger("145188775577763990151158743208307020242261438098488931355057091965" +
            "931517706595657435907891265414916764399268423699130577757433083166" +
            "651158914570105971074227669275788291575622090199821297575654322355" +
            "049043101306108213104080801056529374892690144291505781966373045481" +
            "8359472391642885328171302299245556663073719855")).equals(ONE))
        {
            throw new IllegalArgumentException("RSA modulus has a small prime factor");
        }

        // TODO: add additional primePower/Composite test - expensive!!

        return modulus;
    }

    public BigInteger getModulus()
    {
        return modulus;
    }

    public BigInteger getExponent()
    {
        return exponent;
    }
}
