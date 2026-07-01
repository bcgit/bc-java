package org.bouncycastle.cms;

/**
 * Exception thrown when a recipient is asked to recover content protected under a content-encryption
 * algorithm that is not in the recipient's configured allowed set (see
 * {@code Jce*Recipient.setAllowedContentAlgorithms}).
 */
public class CMSAlgorithmNotAllowedException
    extends CMSException
{
    public CMSAlgorithmNotAllowedException(
        String msg)
    {
        super(msg);
    }

    public CMSAlgorithmNotAllowedException(
        String msg,
        Exception e)
    {
        super(msg, e);
    }
}
