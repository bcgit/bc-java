package org.bouncycastle.pkcs.test;

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
        TestSuite suite = new TestSuite("PKCS Tests");
        
        suite.addTestSuite(PfxPduTest.class);

        return suite;
    }
}
