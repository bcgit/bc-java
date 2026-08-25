package org.bouncycastle.crypto.signers.lms;

class LMSException extends Exception
{
    public LMSException()
    {
    }

    public LMSException(String message)
    {
        super(message);
    }

    public LMSException(String message, Throwable cause)
    {
        super(message, cause);
    }

    public LMSException(Throwable cause)
    {
        super(cause);
    }
}
