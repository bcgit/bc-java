package org.bouncycastle.cert.crmf;

public class CRMFException
    extends Exception
{
    private Throwable cause;

    public CRMFException(String msg)
    {
        this(msg, null);
    }

    public CRMFException(String msg, Throwable cause)
    {
        super(msg);

        this.cause = cause;
    }

    public Throwable getCause()
    {
        return cause;
    }
}