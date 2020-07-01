package org.bouncycastle.jce.provider.test;

import java.security.Provider;
import java.security.Security;

import junit.framework.TestCase;
import org.bouncycastle.util.test.SimpleTestResult;

public class SimpleTestTest
    extends TestCase
{
    public void testJCE()
    {
        org.bouncycastle.util.test.Test[] tests = RegressionTest.tests;

        for (int i = 0; i != tests.length; i++)
        {
            SimpleTestResult result = (SimpleTestResult)tests[i].perform();

            if (!result.isSuccessful())
            {
                if (result.getException() != null)
                {
                    result.getException().printStackTrace();
                }
                fail("index " + i + " " + result.toString());
            }
        }
    }
}
