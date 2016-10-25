package org.bouncycastle.tls;

import org.bouncycastle.tls.crypto.TlsECConfig;

public interface TlsECConfigVerifier
{
    /**
     * Check whether the given EC configuration is acceptable for use.
     * 
     * @param ecConfig the {@link TlsECConfig} to check
     * @return true if (and only if) the specified configuration is acceptable
     */
    boolean accept(TlsECConfig ecConfig);
}
