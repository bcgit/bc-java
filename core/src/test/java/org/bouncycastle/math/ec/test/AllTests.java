package org.bouncycastle.math.ec.test;

import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

import junit.framework.Test;
import junit.framework.TestSuite;

public class AllTests 
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

        suite.addTest(ECAlgorithmsTest.suite());
        suite.addTest(ECPointTest.suite());

        return suite;
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
}
