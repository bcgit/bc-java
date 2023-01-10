package org.bouncycastle.mls.test;

import org.bouncycastle.PrintTestResult;
import org.bouncycastle.mls.Hello;

import junit.framework.TestCase;
import junit.framework.TestSuite;

public class HelloTest
    extends TestCase
{
    public void testHello()
        throws Exception
    {
        String name = "World";
        String expected = "Hello, World!";
        String actual = Hello.sayHello(name);
        assertEquals(expected, actual);
    }

    public static TestSuite suite()
    {
        return new TestSuite(HelloTest.class);
    }

    public static void main(String[] args)
        throws Exception
    {
        PrintTestResult.printResult(junit.textui.TestRunner.run(suite()));
    }
}
