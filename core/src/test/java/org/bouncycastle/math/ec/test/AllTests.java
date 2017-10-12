package org.bouncycastle.math.ec.test;

import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

import junit.extensions.TestSetup;
import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

public class AllTests
    extends TestCase
{
    public static void main (String[] args) 
        throws Exception
    {
        junit.textui.TestRunner.run(suite());
    }
    
    public static Test suite() 
        throws Exception
    {   
        TestSuite suite = new TestSuite("EC Math tests");

        suite.addTestSuite(ECAlgorithmsTest.class);
        suite.addTestSuite(ECPointTest.class);
        suite.addTestSuite(FixedPointTest.class);

        return new BCTestSetup(suite);
    }

    static List enumToList(Enumeration en)
    {
        List rv = new ArrayList();

        while (en.hasMoreElements())
        {
            rv.add(en.nextElement());
        }

        return rv;
    }

    static class BCTestSetup
        extends TestSetup
    {
        public BCTestSetup(Test test)
        {
            super(test);
        }

        protected void setUp()
        {

        }

        protected void tearDown()
        {

        }
    }
}
