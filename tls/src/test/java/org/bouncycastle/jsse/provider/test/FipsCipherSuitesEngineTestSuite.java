package org.bouncycastle.jsse.provider.test;

import junit.framework.Test;
import junit.framework.TestSuite;

public class FipsCipherSuitesEngineTestSuite
    extends TestSuite
{
    public FipsCipherSuitesEngineTestSuite()
    {
        super("FIPS CipherSuites : SSLEngine");
    }

    public static Test suite()
        throws Exception
    {
        return CipherSuitesEngineTestSuite.createSuite(new FipsCipherSuitesEngineTestSuite(), "FIPS", true, new CipherSuitesFilter()
        {
            public boolean isIgnored(String cipherSuite)
            {
                return false;
            }

            public boolean isPermitted(String cipherSuite)
            {
                return FipsCipherSuitesTestSuite.isFipsSupportedCipherSuites(cipherSuite);
            }
        });
    }
}
