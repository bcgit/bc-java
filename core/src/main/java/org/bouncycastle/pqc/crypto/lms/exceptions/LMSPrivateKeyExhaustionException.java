package org.bouncycastle.pqc.crypto.lms.exceptions;

public class LMSPrivateKeyExhaustionException
    extends LMSException
{
    public LMSPrivateKeyExhaustionException()
    {
    }

    public LMSPrivateKeyExhaustionException(String message)
    {
        super(message);
    }

    public LMSPrivateKeyExhaustionException(String message, Throwable cause)
    {
        super(message, cause);
    }

    public LMSPrivateKeyExhaustionException(Throwable cause)
    {
        super(cause);
    }

    public LMSPrivateKeyExhaustionException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace)
    {
        super(message, cause, enableSuppression, writableStackTrace);
    }
}
