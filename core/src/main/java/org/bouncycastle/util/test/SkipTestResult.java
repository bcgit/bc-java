package org.bouncycastle.util.test;

public class SkipTestResult
    implements TestResult
{

   private final String message;

    public SkipTestResult(String message)
    {
        this.message = message;
    }

    public boolean isSuccessful()
    {
        return false;
    }

    public Throwable getException()
    {
        return null;
    }

    public String getMessage()
    {
        return message;
    }

    @Override
    public String toString()
    {
        return "SKIPPED: "+message;
    }
}
