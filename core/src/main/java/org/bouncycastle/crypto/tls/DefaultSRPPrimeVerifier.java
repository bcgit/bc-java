package org.bouncycastle.crypto.tls;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.crypto.agreement.srp.SRP6GroupParameters;

/**
 * SRP prime verifier that accepts any N from RFC 5054 appendix A
 * and rejects all others.
 * @author Richard
 *
 */
public class DefaultSRPPrimeVerifier implements SRPPrimeVerifier
{

    private static final List ALLOWED_PRIMES;
    
    public boolean accept(BigInteger prime)
    {
        return ALLOWED_PRIMES.contains(prime);
    }

    static {
        ALLOWED_PRIMES = new ArrayList();
        ALLOWED_PRIMES.add(SRP6GroupParameters.PRIME_1024);
        ALLOWED_PRIMES.add(SRP6GroupParameters.PRIME_1536);
        ALLOWED_PRIMES.add(SRP6GroupParameters.PRIME_2048);
        ALLOWED_PRIMES.add(SRP6GroupParameters.PRIME_3072);
        ALLOWED_PRIMES.add(SRP6GroupParameters.PRIME_4096);
        ALLOWED_PRIMES.add(SRP6GroupParameters.PRIME_6144);
        ALLOWED_PRIMES.add(SRP6GroupParameters.PRIME_8192);
    }
    
}
