package org.bouncycastle.crypto.params;

import java.math.BigInteger;

import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.math.Primes;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.Properties;

public class RSAKeyParameters
    extends AsymmetricKeyParameter
{
    public static BigInteger validateModulus(BigInteger modulus)
    {
        return validate(modulus, false);
    }

//    private static final BigIntegers.Cache validated = new BigIntegers.Cache();

    private BigInteger modulus;
    private BigInteger exponent;

    public RSAKeyParameters(boolean isPrivate, BigInteger modulus, BigInteger exponent)
    {
        this(isPrivate, modulus, exponent, false);
    }   

    public RSAKeyParameters(boolean isPrivate, BigInteger modulus, BigInteger exponent, boolean isInternal)
    {
        super(isPrivate);

        if (!isPrivate && !exponent.testBit(0))
        {
            throw new IllegalArgumentException("RSA publicExponent is even");
        }

        // only check public keys
        this.modulus = isPrivate ? modulus : validate(modulus, isInternal);
        this.exponent = exponent;
    }

    private static BigInteger validate(BigInteger modulus, boolean isInternal)
    {
//        if (validated.contains(modulus))
//        {
//            return modulus;
//        }

        if (!isInternal)
        {
            if (!modulus.testBit(0))
            {
                throw new IllegalArgumentException("RSA modulus is even");
            }

            // If you need to set this you need to have a serious word to whoever is generating your keys.
            if (Properties.isOverrideSet("org.bouncycastle.rsa.allow_unsafe_mod"))
            {
                return modulus;
            }

            int maxBitLength = Properties.asInteger("org.bouncycastle.rsa.max_size", 16384);
            if (maxBitLength < modulus.bitLength())
            {
                throw new IllegalArgumentException("RSA modulus out of range");
            }

            if (BigIntegers.hasAnySmallFactorsVar(modulus))
            {
                throw new IllegalArgumentException("RSA modulus has a small prime factor");
            }

            int defaultIterations = getMRIterations(modulus.bitLength() / 2);
            int iterations = Properties.asInteger("org.bouncycastle.rsa.max_mr_tests", defaultIterations);
            if (iterations > 0)
            {
                Primes.MROutput mr = Primes.enhancedMRProbablePrimeTest(modulus,
                    CryptoServicesRegistrar.getSecureRandom(), iterations);
                if (!mr.isProvablyComposite())
                {
                    throw new IllegalArgumentException("RSA modulus is not composite");
                }
            }
        }

        //validated.add(modulus);
        return modulus;
    }

    private static int getMRIterations(int bits)
    {
        int iterations = bits >= 1536 ? 3
            : bits >= 1024 ? 4
            : bits >= 512 ? 7
            : 50;
        return iterations;
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
