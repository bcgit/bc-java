package org.bouncycastle.cert.plants;

/**
 * Thrown when a Merkle tree inclusion or consistency proof fails validation.
 */
public class InvalidProofException
    extends Exception
{
    public InvalidProofException(String message)
    {
        super(message);
    }
}
