package org.bouncycastle.tls;

import org.bouncycastle.tls.crypto.TlsDHConfig;

/**
 * Interface a class for verifying Diffie-Hellman config needs to conform to.
 */
public interface TlsDHConfigVerifier
{
    /**
     * Check whether the given DH configuration is acceptable for use.
     * 
     * @param dhConfig the {@link TlsDHConfig} to check
     * @return true if (and only if) the specified configuration is acceptable
     */
    boolean accept(TlsDHConfig dhConfig);
}
