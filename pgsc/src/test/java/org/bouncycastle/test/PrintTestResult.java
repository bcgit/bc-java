package org.bouncycastle.test;


import junit.framework.TestResult;

import java.util.Enumeration;

public class PrintTestResult
{
    public static void printResult(TestResult result)
    {
        Enumeration e = result.failures();
        if (e != null)
        {
            while (e.hasMoreElements())
            {
                // -DM System.out.println
                System.out.println(e.nextElement());
            }
        }

        e = result.errors();
        if (e != null)
        {
            while (e.hasMoreElements())
            {
                // -DM System.out.println
                System.out.println(e.nextElement());
            }
        }

        if (!result.wasSuccessful())
        {
            // -DM System.exit
            System.exit(1);
        }
    }
}

