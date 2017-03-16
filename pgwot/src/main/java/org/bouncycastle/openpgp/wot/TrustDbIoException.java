package org.bouncycastle.openpgp.wot;

/**
 * Exception thrown by {@link org.bouncycastle.openpgp.wot.internal.TrustDbIo TrustDbIo}
 * when reading from or writing to the trust database file failed.
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
