package org.bouncycastle.tsp.ers;

/**
 * Exception thrown when verification of an RFC 4998 PartialHashtree fails.
 */
public class PartialHashTreeVerificationException
    extends ERSException
{
    public PartialHashTreeVerificationException(final String message)
    {
        super(message);
    }
}
