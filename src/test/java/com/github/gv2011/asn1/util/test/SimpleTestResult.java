package com.github.gv2011.asn1.util.test;

import com.github.gv2011.asn1.util.Strings;

public class SimpleTestResult implements TestResult
{
    private static final String SEPARATOR = Strings.lineSeparator();

    private final boolean             success;
    private final String              message;
    private Throwable           exception;

    public SimpleTestResult(final boolean success, final String message)
    {
        this.success = success;
        this.message = message;
    }

    public SimpleTestResult(final boolean success, final String message, final Throwable exception)
    {
        this.success = success;
        this.message = message;
        this.exception = exception;
    }

    public static TestResult successful(
        final LegacyTest test,
        final String message)
    {
        return new SimpleTestResult(true, test.getName() + ": " + message);
    }

    public static TestResult failed(
        final LegacyTest test,
        final String message)
    {
        return new SimpleTestResult(false, test.getName() + ": " + message);
    }

    public static TestResult failed(
        final LegacyTest test,
        final String message,
        final Throwable t)
    {
        return new SimpleTestResult(false, test.getName() + ": " + message, t);
    }

    public static TestResult failed(
        final LegacyTest test,
        final String message,
        final Object expected,
        final Object found)
    {
        return failed(test, message + SEPARATOR + "Expected: " + expected + SEPARATOR + "Found   : " + found);
    }

    public static String failedMessage(final String algorithm, final String testName, final String expected,
            final String actual)
    {
        final StringBuffer sb = new StringBuffer(algorithm);
        sb.append(" failing ").append(testName);
        sb.append(SEPARATOR).append("    expected: ").append(expected);
        sb.append(SEPARATOR).append("    got     : ").append(actual);

        return sb.toString();
    }

    @Override
    public boolean isSuccessful()
    {
        return success;
    }

    @Override
    public String toString()
    {
        return message;
    }

    @Override
    public Throwable getException()
    {
        return exception;
    }
}
