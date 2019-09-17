package org.bouncycastle.jsse.provider;

import java.util.HashSet;
import java.util.Set;

import org.bouncycastle.tls.CipherSuite;

class ProvAlgorithmDecomposer
    extends JcaAlgorithmDecomposer
{
    static final ProvAlgorithmDecomposer INSTANCE = new ProvAlgorithmDecomposer();

    private ProvAlgorithmDecomposer() {}

    public Set<String> decompose(String algorithm)
    {
        if (algorithm.startsWith("TLS_"))
        {
            CipherSuiteInfo cipherSuiteInfo = ProvSSLContextSpi.getCipherSuiteInfo(algorithm);
            if (null != cipherSuiteInfo
                && !CipherSuite.isSCSV(cipherSuiteInfo.getCipherSuite()))
            {
                return new HashSet<String>(cipherSuiteInfo.getDecomposition());
            }
        }

        return super.decompose(algorithm);
    }
}
