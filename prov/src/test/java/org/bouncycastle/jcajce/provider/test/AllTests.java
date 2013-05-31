package org.bouncycastle.jcajce.provider.test;

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
        TestSuite suite = new TestSuite("JCAJCE Provider Tests");
        
        suite.addTestSuite(PrivateConstructorTest.class);

        return suite;
    }
}
