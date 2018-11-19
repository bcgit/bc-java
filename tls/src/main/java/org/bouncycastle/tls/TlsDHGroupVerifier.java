package org.bouncycastle.tls;

import org.bouncycastle.tls.crypto.DHGroup;

/**
 * Interface for verifying explicit Diffie-Hellman group parameters.
 */
public interface TlsDHGroupVerifier
{
    /**
     * Check whether the given DH group is acceptable for use.
     * 
     * @param dhGroup the {@link DHGroup} to check
     * @return true if (and only if) the specified group is acceptable
     */
    boolean accept(DHGroup dhGroup);
}
