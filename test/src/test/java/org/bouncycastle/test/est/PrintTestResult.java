package org.bouncycastle.test.est;


import java.util.Enumeration;

import junit.framework.TestFailure;
import junit.framework.TestResult;

public class PrintTestResult
{
    public static void printResult(TestResult result)
    {
        Enumeration e = result.failures();
        if (e != null)
        {
            while (e.hasMoreElements())
            {
                System.out.println(e.nextElement());
            }
        }

        e = result.errors();
        if (e != null)
        {
            while (e.hasMoreElements())
            {
                System.out.println(e.nextElement());
            }
        }

        if (!result.wasSuccessful())
        {
            System.exit(1);
        }
    }
}

