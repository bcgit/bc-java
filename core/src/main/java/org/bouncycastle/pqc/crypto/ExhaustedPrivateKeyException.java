package org.bouncycastle.pqc.crypto;

/**
 * Exception thrown by a stateful signature algorithm when the private key counter is exhausted.
 */
public class ExhaustedPrivateKeyException
    extends IllegalStateException
{
    public ExhaustedPrivateKeyException(String msg)
    {
        super(msg);
    }
}
