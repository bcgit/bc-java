package org.bouncycastle.est;


/**
 * Interface for a Source which can only produce up to a certain number of bytes.
 */
public interface LimitedSource
{
    /**
     * Return the maximum number of bytes available from this source.
     *
     * @return the max bytes this source can produce.
     */
    Long getAbsoluteReadLimit();
}
