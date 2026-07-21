package org.bouncycastle.tsp.cms;

import org.bouncycastle.tsp.TimeStampToken;

/**
 * Thrown during validation of a {@link CMSTimeStampedData} when a calculated digest
 * does not match the message imprint recorded in a time stamp token, or when a token
 * being checked is not associated with the evidence present in the message. The
 * offending token is retrievable via {@link #getTimeStampToken()}.
 */
public class ImprintDigestInvalidException
    extends Exception
{
    private TimeStampToken token;

    public ImprintDigestInvalidException(String message, TimeStampToken token)
    {
        super(message);

        this.token = token;
    }

    /**
     * Return the time stamp token whose imprint check failed.
     *
     * @return the token associated with this exception.
     */
    public TimeStampToken getTimeStampToken()
    {
        return token;
    }
}
