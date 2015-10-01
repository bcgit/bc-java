package org.bouncycastle.openpgp.wot;

import org.bouncycastle.openpgp.wot.internal.TrustDbIo;

/**
 * Exception thrown by {@link TrustDbIo} when reading from or writing to the trust database failed.
 */
public class TrustDbIoException extends TrustDbException
{
    private static final long serialVersionUID = 1L;

    public TrustDbIoException()
    {
    }

    public TrustDbIoException(String message)
    {
        super(message);
    }

    public TrustDbIoException(Throwable cause)
    {
        super(cause);
    }

    public TrustDbIoException(String message, Throwable cause)
    {
        super(message, cause);
    }
}
