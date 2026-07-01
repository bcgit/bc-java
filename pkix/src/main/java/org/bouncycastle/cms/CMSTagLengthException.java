package org.bouncycastle.cms;

/**
 * Exception thrown when a recipient is asked to recover AEAD-protected content whose authentication
 * tag is shorter than the recipient's configured minimum tag size (see
 * {@code Jce*Recipient.setMinimumTagSize}).
 */
public class CMSTagLengthException
    extends CMSException
{
    public CMSTagLengthException(
        String msg)
    {
        super(msg);
    }

    public CMSTagLengthException(
        String msg,
        Exception e)
    {
        super(msg, e);
    }
}
