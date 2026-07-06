package org.bouncycastle.est.test;

import java.security.Security;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.test.PrintTestResult;

public class AllTests
    extends TestCase
{
    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;

    public void setUp()
    {
        if (Security.getProvider(BC) != null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public static void main(String[] args)
        throws Exception
    {
        Security.addProvider(new BouncyCastleProvider());

        PrintTestResult.printResult(junit.textui.TestRunner.run(suite()));
    }

    public static Test suite()
        throws Exception
    {
        TestSuite suite = new TestSuite("EST tests");

        suite.addTestSuite(ESTParsingTest.class);
        suite.addTestSuite(HostNameAuthorizerMatchTest.class);
        suite.addTestSuite(TestHostNameAuthorizer.class);
        suite.addTestSuite(ESTResponseTest.class);
        suite.addTestSuite(Rfc7894AttributesTest.class);
        // HttpUtilTest lives in the package-private org.bouncycastle.est package (it exercises
        // HttpUtil.splitCSL) and is run from that package's own AllTests, so the signed-jar
        // legacy Ant builds can drop it without breaking this shared suite.

        return new ESTTestSetup(suite);
    }
}
