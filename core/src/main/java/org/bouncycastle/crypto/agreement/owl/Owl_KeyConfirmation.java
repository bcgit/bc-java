package org.example;

import java.math.BigInteger;

/**
 * The payload sent/received during the explicit key confirmation stage of the protocol,
 * <p>
 * Both {@link Owl_Client} and {@link Owl_Server} create and send an instance
 * of this payload to the other.
 * The payload to send should be created via
 * {@link Owl_Client#initiateKeyConfirmation(BigInteger)}
 * or {@link Owl_Server#initiateKeyConfirmation(BigInteger)}.
 * <p>
 * Both {@link Owl_Client} and {@link Owl_Server} must also validate the payload
 * received from the other.
 * The received payload should be validated via
 * {@link Owl_Client#validateKeyConfirmation(Owl_KeyConfirmation, BigInteger)}
 * {@link Owl_Server#validateKeyConfirmation(Owl_KeyConfirmation, BigInteger)}
 */
public class Owl_KeyConfirmation
{

    /**
     * The id of either {@link Owl_Client} or {@link Owl_Server} who created/sent this payload.
     */
    private final String id;

    /**
     * The value of MacTag, as computed by the key confirmation round.
     *
     * @see Owl_Util#calculateMacTag
     */
    private final BigInteger macTag;

    /**
     * Constructor of Owl_KeyConfirmation
     * @param id The identity of the sender
     * @param magTag The key confirmation string
     */
    public Owl_KeyConfirmation(String id, BigInteger magTag)
    {
        this.id = id;
        this.macTag = magTag;
    }

    /**
     * Get the identity of the sender
     * @return The identity of the sender
     */
    public String getId()
    {
        return id;
    }

    /**
     * Get the MAC tag which serves as a key confirmation string
     * @return The MAC tag
     */
    public BigInteger getMacTag()
    {
        return macTag;
    }

}