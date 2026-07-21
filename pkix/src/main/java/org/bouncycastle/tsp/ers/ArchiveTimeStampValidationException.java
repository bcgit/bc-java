package org.bouncycastle.tsp.ers;

/**
 * Exception thrown when validation of an RFC 4998 ArchiveTimeStamp fails -
 * for example when the expected data hash is not present in the reduced
 * hash tree, or the recovered root hash does not match the time-stamp imprint.
 */
public class ArchiveTimeStampValidationException
    extends ERSException
{
    public ArchiveTimeStampValidationException(final String message)
    {
        super(message);
    }
}

