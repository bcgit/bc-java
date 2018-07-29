package org.bouncycastle.crypto.tls;

import org.bouncycastle.crypto.params.DHParameters;

/**
 * Interface a class for verifying Diffie-Hellman parameters needs to conform to.
 */
public interface TlsDHVerifier
{
    /**
     * Check whether the given DH parameters are acceptable for use.
     * 
     * @param dhParameters the {@link DHParameters} to check
     * @return true if (and only if) the specified parameters are acceptable
     */
    boolean accept(DHParameters dhParameters);
}
