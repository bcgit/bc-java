package org.bouncycastle.pqc.crypto;

/**
 * Exception thrown by a stateful signature algorithm when the private key counter is exhausted.
 *
 * @deprecated use org.bouncycastle.crypto.ExhaustedPrivateKeyException instead. This class now
 * extends it, so a catch of the replacement catches this one as well.
 */
public class ExhaustedPrivateKeyException
    extends org.bouncycastle.crypto.ExhaustedPrivateKeyException
{
    public ExhaustedPrivateKeyException(String msg)
    {
        super(msg);
    }
}
