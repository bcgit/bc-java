package org.bouncycastle.crypto.test.ntru;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

public class AllTests
    extends TestCase
{
    public static void main (String[] args)
    {
        junit.textui.TestRunner.run(suite());
    }
    
    public static Test suite()
    {
        TestSuite suite = new TestSuite("NTRU Key/Parameter Tests");
        
        suite.addTestSuite(EncryptionKeyTest.class);
        suite.addTestSuite(NTRUEncryptionParametersTest.class);
        suite.addTestSuite(NTRUSignatureParametersTest.class);

        return suite;
    }
}
