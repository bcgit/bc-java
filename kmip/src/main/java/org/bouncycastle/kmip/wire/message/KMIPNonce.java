package org.bouncycastle.kmip.wire.message;

/**
 * A Nonce object is a structure used by the server to send a random value to the client. The Nonce
 * Identifier is assigned by the server and used to identify the Nonce object. The Nonce Value consists of
 * the random data created by the server.
 * */
public class KMIPNonce
{
    private byte[] nonceID;
    private byte[] nonceValue;

    /**
     * Constructor to initialize the Nonce with ID and Value.
     *
     * @param nonceID    The identifier of the Nonce.
     * @param nonceValue The random value of the Nonce.
     */
    public KMIPNonce(byte[] nonceID, byte[] nonceValue)
    {
        if (nonceID == null || nonceID.length == 0)
        {
            throw new IllegalArgumentException("Nonce ID cannot be null or empty.");
        }
        if (nonceValue == null || nonceValue.length == 0)
        {
            throw new IllegalArgumentException("Nonce Value cannot be null or empty.");
        }
        this.nonceID = nonceID;
        this.nonceValue = nonceValue;
    }

    /**
     * Gets the Nonce ID.
     *
     * @return The identifier of the Nonce.
     */
    public byte[] getNonceID()
    {
        return nonceID;
    }

    /**
     * Sets the Nonce ID.
     *
     * @param nonceID The identifier of the Nonce.
     */
    public void setNonceID(byte[] nonceID)
    {
        if (nonceID == null || nonceID.length == 0)
        {
            throw new IllegalArgumentException("Nonce ID cannot be null or empty.");
        }
        this.nonceID = nonceID;
    }

    /**
     * Gets the Nonce Value.
     *
     * @return The random value of the Nonce.
     */
    public byte[] getNonceValue()
    {
        return nonceValue;
    }

    /**
     * Sets the Nonce Value.
     *
     * @param nonceValue The random value of the Nonce.
     */
    public void setNonceValue(byte[] nonceValue)
    {
        if (nonceValue == null || nonceValue.length == 0)
        {
            throw new IllegalArgumentException("Nonce Value cannot be null or empty.");
        }
        this.nonceValue = nonceValue;
    }
}
