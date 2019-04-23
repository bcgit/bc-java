package org.bouncycastle.crypto.params;

import java.math.BigInteger;

import org.bouncycastle.util.Properties;

public class RSAKeyParameters
    extends AsymmetricKeyParameter
{
    // Hexadecimal value of the product of the 131 smallest odd primes from 3 to 743
    private static final BigInteger SMALL_PRIMES_PRODUCT = new BigInteger(
              "8138e8a0fcf3a4e84a771d40fd305d7f4aa59306d7251de54d98af8fe95729a1f"
            + "73d893fa424cd2edc8636a6c3285e022b0e3866a565ae8108eed8591cd4fe8d2"
            + "ce86165a978d719ebf647f362d33fca29cd179fb42401cbaf3df0c614056f9c8"
            + "f3cfd51e474afb6bc6974f78db8aba8e9e517fded658591ab7502bd41849462f",
        16);

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

        // If you need to set this you need to have a serious word to whoever is generating
        // your keys.
        if (Properties.isOverrideSet("org.bouncycastle.rsa.allow_unsafe_mod"))
        {
            return modulus;
        }

        if (!modulus.gcd(SMALL_PRIMES_PRODUCT).equals(ONE))
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
