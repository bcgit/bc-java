package org.bouncycastle.crypto.tls;

import java.util.Vector;

import org.bouncycastle.crypto.params.SRP6GroupParameters;

public interface TlsSRPGroupVerifier
{
    /**
     * Check whether a given set of SRP group parameters are acceptable for use.
     * 
     * @param group the {@link Vector} to check
     * @return true if (and only if) the specified group parameters are acceptable
     */
    boolean accept(SRP6GroupParameters group);
}
