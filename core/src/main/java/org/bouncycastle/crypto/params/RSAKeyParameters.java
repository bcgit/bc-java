package org.bouncycastle.crypto.params;

import java.math.BigInteger;

import javax.security.auth.Destroyable;

import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.math.Primes;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.Properties;

public class RSAKeyParameters
    extends AsymmetricKeyParameter
    implements Destroyable
{
    public static BigInteger validateModulus(BigInteger modulus)
    {
        return validate(modulus, false);
    }

    private static final BigIntegers.Cache validated = new BigIntegers.Cache();

    private BigInteger modulus;
    private BigInteger exponent;

    private volatile boolean destroyed;

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

        this.modulus = validate(modulus, isInternal);
        this.exponent = exponent;
    }

    private static BigInteger validate(BigInteger modulus, boolean isInternal)
    {
        if (validated.contains(modulus))
        {
            return modulus;
        }

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

            if (BigIntegers.hasAnySmallFactors(modulus))
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

        validated.add(modulus);
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
        return valueWithCheck(exponent);
    }

    BigInteger valueWithCheck(BigInteger value)
    {
        // the null check catches a destroy() in progress whose flag write is not yet visible;
        // as BigInteger is immutable a non-null snapshot is always the intact pre-destroy value.
        if (destroyed || value == null)
        {
            throw new IllegalStateException("key destroyed");
        }

        return value;
    }

    /**
     * Destroy this object, dropping its reference to the exponent. The (public) modulus is
     * retained.
     * <p>
     * As {@link BigInteger} is immutable the exponent cannot be zeroized in place; destruction
     * drops the internal reference so the value becomes unreachable (cleared on garbage
     * collection). After destruction {@link #getExponent()} throws
     * {@link IllegalStateException}.
     * <p>
     * This type also backs RSA public keys; destroying one of those drops the (non-secret)
     * public exponent, which is harmless but renders the key unusable.
     */
    public synchronized void destroy()
    {
        if (!destroyed)
        {
            destroyed = true;
            this.exponent = null;
        }
    }

    public boolean isDestroyed()
    {
        return destroyed;
    }
}
