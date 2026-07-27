package org.bouncycastle.pkcs.test;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.bouncycastle.test.PrintTestResult;

public class AllTests
    extends TestCase
{
    public static void main (String[] args)
    {
        PrintTestResult.printResult(junit.textui.TestRunner.run(suite()));
    }

    // NOTE: jdk1.3 overlay. PKCS12UtilTest and PBETest are excluded from the jdk1.3 build
    // (KeyStore.SecretKeyEntry / other post-1.3 APIs, ant/jdk13.xml) so their references are
    // dropped here.
    public static Test suite()
    {
        TestSuite suite = new TestSuite("PKCS Tests");

        suite.addTestSuite(PfxPduTest.class);
        suite.addTestSuite(PKCS10Test.class);
        suite.addTestSuite(PKCS8Test.class);
        suite.addTestSuite(PKCS12PfxPduSecretKeyTest.class);

        return new BCTestSetup(suite);
    }
}
