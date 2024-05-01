package org.bouncycastle.bcpg.test;

import java.security.Security;

import junit.extensions.TestSetup;
import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.test.PrintTestResult;
import org.bouncycastle.util.test.SimpleTestResult;

public class AllTests
        extends TestCase
{

    public void testPacketParsing()
    {
        Security.addProvider(new BouncyCastleProvider());

        org.bouncycastle.util.test.Test[] tests = new org.bouncycastle.util.test.Test[]
                {
                        new SignaturePacketTest(),
                        new OnePassSignaturePacketTest(),
                        new OpenPgpMessageTest(),
                        new FingerprintUtilTest()
                };

        for (int i = 0; i != tests.length; i++)
        {
            SimpleTestResult result = (SimpleTestResult)tests[i].perform();

            if (!result.isSuccessful())
            {
                fail(result.toString());
            }
        }
    }


    public static void main(String[] args)
    {
        PrintTestResult.printResult(junit.textui.TestRunner.run(suite()));
    }

    public static Test suite()
    {
        TestSuite suite = new TestSuite("OpenPGP Packet Tests");

        suite.addTestSuite(AllTests.class);

        return new BCPacketTests(suite);
    }

    static class BCPacketTests
            extends TestSetup
    {
        public BCPacketTests(Test test)
        {
            super(test);
        }

        protected void setUp()
        {
            Security.addProvider(new BouncyCastleProvider());
        }

        protected void tearDown()
        {
            Security.removeProvider("BC");
        }
    }
}
