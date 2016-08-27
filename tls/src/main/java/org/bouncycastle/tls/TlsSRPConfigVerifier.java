package org.bouncycastle.tls;

import org.bouncycastle.tls.crypto.TlsSRPConfig;

public interface TlsSRPConfigVerifier
{
    /**
     * Check whether the given SRP configuration is acceptable for use.
     * 
     * @param srpConfig the {@link TlsSRPConfig} to check
     * @return true if (and only if) the specified configuration is acceptable
     */
    boolean accept(TlsSRPConfig srpConfig);
}
