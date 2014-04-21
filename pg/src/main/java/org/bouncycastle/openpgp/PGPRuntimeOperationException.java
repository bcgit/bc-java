package org.bouncycastle.openpgp;

public class PGPRuntimeOperationException
    extends RuntimeException
{
    private final Throwable cause;

    public PGPRuntimeOperationException(String message, Throwable cause)
    {
        super(message);

        this.cause = cause;
    }

    public Throwable getCause()
    {
        return cause;
    }
}
