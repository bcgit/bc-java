package org.bouncycastle.mime.test;

import java.security.Security;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

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

        junit.textui.TestRunner.run(suite());
    }

    public static Test suite()
        throws Exception
    {
        TestSuite suite = new TestSuite("MIME tests");

        suite.addTestSuite(Base64TransferEncodingTest.class);
        suite.addTestSuite(MimeParserTest.class);
        suite.addTestSuite(MultipartParserTest.class);
        suite.addTestSuite(QuotedPrintableTest.class);
        suite.addTestSuite(TestBoundaryLimitedInputStream.class);
        suite.addTestSuite(TestSMIMEEnveloped.class);
        suite.addTestSuite(TestSMIMESigned.class);
        suite.addTestSuite(TestSMIMESignEncrypt.class);

        return new MIMETestSetup(suite);
    }
}
