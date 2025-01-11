package org.bouncycastle.jsse.provider.test;

import junit.extensions.TestSetup;
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
        FipsTestUtils.setupFipsSuite();

        TestSuite suite = CipherSuitesEngineTestSuite.createSuite(new FipsCipherSuitesEngineTestSuite(), "FIPS", true,
            new CipherSuitesFilter()
        {
            public boolean isIgnored(String cipherSuite)
            {
                return false;
            }

            public boolean isPermitted(String cipherSuite)
            {
                return FipsTestUtils.isFipsCipherSuite(cipherSuite);
            }
        });

        FipsTestUtils.teardownFipsSuite();

        return new TestSetup(suite)
        {
            @Override
            protected void setUp() throws Exception
            {
                FipsTestUtils.setupFipsSuite();
            }

            @Override
            protected void tearDown() throws Exception
            {
                FipsTestUtils.teardownFipsSuite();
            }
        };
    }
}
