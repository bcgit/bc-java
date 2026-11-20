package org.bouncycastle.crypto.params;

import java.math.BigInteger;
import java.util.Collections;
import java.util.Map;
import java.util.WeakHashMap;

import javax.security.auth.Destroyable;

import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.math.Primes;

public class DHPrivateKeyParameters
    extends DHKeyParameters
    implements Destroyable
{
    // q values already found prime, kept while some parameter set still holds the q
    private static final Map primeQs = Collections.synchronizedMap(new WeakHashMap());

    private BigInteger      x;

    private volatile boolean destroyed;
    private int destroyedHashCode;

    /**
     * Base constructor.
     *
     * @param x the private value.
     * @param params the domain parameters.
     * @throws IllegalArgumentException if params carries a q that is not prime: SP 800-56A requires a prime q, and
     * with a composite q the subgroup check on a peer's public value admits elements of small order, which reveal
     * the private value modulo each small factor of q.
     */
    public DHPrivateKeyParameters(
        BigInteger      x,
        DHParameters    params)
    {
        super(true, params);

        BigInteger q = params.getQ();
        if (q != null && !isPrimeQ(q))
        {
            throw new IllegalArgumentException("DH parameter q is not prime");
        }

        this.x = x;
    }

    private static boolean isPrimeQ(BigInteger q)
    {
        if (primeQs.containsKey(q))
        {
            return true;
        }

        boolean isPrime;
        int bits = q.bitLength();
        if (q.signum() <= 0 || bits < 2)
        {
            isPrime = false;
        }
        else if (bits <= 8)
        {
            // hasAnySmallFactors would count a small prime q as its own factor
            isPrime = q.isProbablePrime(100);
        }
        else if (Primes.hasAnySmallFactors(q))
        {
            isPrime = false;
        }
        else
        {
            // FIPS 186-4 C.3, error probability 2^-100
            int iterations = bits >= 1536 ? 4 : bits >= 1024 ? 5 : bits >= 512 ? 7 : 27;

            isPrime = Primes.isMRProbablePrime(q, CryptoServicesRegistrar.getSecureRandom(), iterations);
        }

        if (isPrime)
        {
            primeQs.put(q, Boolean.TRUE);
        }

        return isPrime;
    }

    public BigInteger getX()
    {
        BigInteger value = x;

        // the null check catches a destroy() in progress whose flag write is not yet visible;
        // as BigInteger is immutable a non-null snapshot is always the intact pre-destroy value.
        if (destroyed || value == null)
        {
            throw new IllegalStateException("key destroyed");
        }

        return value;
    }

    public synchronized int hashCode()
    {
        BigInteger value = x;

        if (value == null)
        {
            return destroyedHashCode;
        }

        DHParameters params = getParameters();
        BigInteger y = params.getG().modPow(value, params.getP());

        return y.hashCode() ^ super.hashCode();
    }
    
    public boolean equals(
        Object  obj)
    {
        if (obj == this)
        {
            return true;
        }

        if (!(obj instanceof DHPrivateKeyParameters))
        {
            return false;
        }

        DHPrivateKeyParameters  other = (DHPrivateKeyParameters)obj;

        BigInteger thisX = this.x;
        BigInteger otherX = other.x;

        // a destroyed key no longer exposes its value, so it is only equal to itself.
        if (destroyed || other.destroyed || thisX == null || otherX == null)
        {
            return false;
        }

        return otherX.equals(thisX) && super.equals(obj);
    }

    /**
     * Destroy this object, dropping its reference to the private value.
     * <p>
     * As {@link BigInteger} is immutable the private value cannot be zeroized in place;
     * destruction drops the internal reference so the value becomes unreachable (cleared on
     * garbage collection). The (public) domain parameters are retained. After destruction
     * {@link #getX()} throws {@link IllegalStateException}, {@link #hashCode()} retains its
     * pre-destruction value and the object is equal only to itself.
     */
    public synchronized void destroy()
    {
        if (!destroyed)
        {
            // freeze the hash before the private value is dropped, so hash containers holding
            // this key keep working.
            try
            {
                this.destroyedHashCode = hashCode();
            }
            catch (RuntimeException e)
            {
                this.destroyedHashCode = -1;
            }

            destroyed = true;
            this.x = null;
        }
    }

    public boolean isDestroyed()
    {
        return destroyed;
    }
}
