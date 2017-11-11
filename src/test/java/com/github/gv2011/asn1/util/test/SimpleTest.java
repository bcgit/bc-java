package com.github.gv2011.asn1.util.test;

import java.io.PrintStream;

import com.github.gv2011.asn1.util.Arrays;

public abstract class SimpleTest
    implements LegacyTest
{
    @Override
    public abstract String getName();

    private TestResult success()
    {
        return SimpleTestResult.successful(this, "Okay");
    }

    protected void fail(
        final String message)
    {
        throw new TestFailedException(SimpleTestResult.failed(this, message));
    }

    protected void fail(
        final String    message,
        final Throwable throwable)
    {
        throw new TestFailedException(SimpleTestResult.failed(this, message, throwable));
    }

    protected void fail(
        final String message,
        final Object expected,
        final Object found)
    {
        throw new TestFailedException(SimpleTestResult.failed(this, message, expected, found));
    }

    protected boolean areEqual(
        final byte[] a,
        final byte[] b)
    {
        return Arrays.areEqual(a, b);
    }

    @Override
    public TestResult perform()
    {
        try
        {
            performTest();

            return success();
        }
        catch (final TestFailedException e)
        {
            return e.getResult();
        }
        catch (final Exception e)
        {
            return SimpleTestResult.failed(this, "Exception: " +  e, e);
        }
    }

    protected static void runTest(
        final LegacyTest        test)
    {
        runTest(test, System.out);
    }

    protected static void runTest(
        final LegacyTest        test,
        final PrintStream out)
    {
        final TestResult      result = test.perform();

        out.println(result.toString());
        if (result.getException() != null)
        {
            result.getException().printStackTrace(out);
        }
    }

    public abstract void performTest()
        throws Exception;
}
