package org.bouncycastle.crypto.engines.test;

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
        TestSuite suite = new TestSuite("NTRU Engine Tests");
        
        suite.addTestSuite(BitStringTest.class);
        suite.addTestSuite(NTRUEncryptTest.class);

        return suite;
    }
}
