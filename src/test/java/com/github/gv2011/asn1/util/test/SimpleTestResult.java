package com.github.gv2011.asn1.util.test;

import com.github.gv2011.asn1.util.Strings;

public class SimpleTestResult implements TestResult
{
    private static final String SEPARATOR = Strings.lineSeparator();

    private boolean             success;
    private String              message;
    private Throwable           exception;

    public SimpleTestResult(boolean success, String message)
    {
        this.success = success;
        this.message = message;
    }

    public SimpleTestResult(boolean success, String message, Throwable exception)
    {
        this.success = success;
        this.message = message;
        this.exception = exception;
    }

    public static TestResult successful(
        LegacyTest test, 
        String message)
    {
        return new SimpleTestResult(true, test.getName() + ": " + message);
    }

    public static TestResult failed(
        LegacyTest test, 
        String message)
    {
        return new SimpleTestResult(false, test.getName() + ": " + message);
    }
    
    public static TestResult failed(
        LegacyTest test, 
        String message, 
        Throwable t)
    {
        return new SimpleTestResult(false, test.getName() + ": " + message, t);
    }
    
    public static TestResult failed(
        LegacyTest test, 
        String message, 
        Object expected, 
        Object found)
    {
        return failed(test, message + SEPARATOR + "Expected: " + expected + SEPARATOR + "Found   : " + found);
    }
    
    public static String failedMessage(String algorithm, String testName, String expected,
            String actual)
    {
        StringBuffer sb = new StringBuffer(algorithm);
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
