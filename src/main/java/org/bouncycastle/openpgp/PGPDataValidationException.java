package org.bouncycastle.openpgp;

/**
 * Thrown if the iv at the start of a data stream indicates the wrong key
 * is being used.
 */
public class PGPDataValidationException 
    extends PGPException
{
    /**
     * @param message
     */
    public PGPDataValidationException(String message)
    {
        super(message);
    }
}
