package org.bouncycastle.crypto.tls;

import java.math.BigInteger;

public interface SRPPrimeVerifier
{

    /**
     * Whether to accept the given safe prime as a value for N.
     * See RFC 5054 section 3.2.
     * @param prime
     * @return True if the prime is acceptable, false if it is not.
     */
    boolean accept(BigInteger prime);
    
}
