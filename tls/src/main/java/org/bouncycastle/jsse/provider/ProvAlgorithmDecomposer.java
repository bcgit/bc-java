package org.bouncycastle.jsse.provider;

import java.util.Set;

import org.bouncycastle.tls.CipherSuite;

class ProvAlgorithmDecomposer
    extends JcaAlgorithmDecomposer
{
    static final ProvAlgorithmDecomposer INSTANCE_TLS = new ProvAlgorithmDecomposer(true);
    static final ProvAlgorithmDecomposer INSTANCE_X509 = new ProvAlgorithmDecomposer(false);

    private final boolean enableTLSAlgorithms;

    private ProvAlgorithmDecomposer(boolean enableTLSAlgorithms)
    {
        this.enableTLSAlgorithms = enableTLSAlgorithms;
    }

    public Set<String> decompose(String algorithm)
    {
        if (algorithm.startsWith("TLS_"))
        {
            CipherSuiteInfo cipherSuiteInfo = ProvSSLContextSpi.getCipherSuiteInfo(algorithm);

            if (null != cipherSuiteInfo && !CipherSuite.isSCSV(cipherSuiteInfo.getCipherSuite()))
            {
                return enableTLSAlgorithms
                    ?   cipherSuiteInfo.getDecompositionTLS()
                    :   cipherSuiteInfo.getDecompositionX509();
            }
        }

        return super.decompose(algorithm);
    }
}
