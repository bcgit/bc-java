package org.bouncycastle.crypto.agreement.owl;

import java.math.BigInteger;

/**
 * The payload sent/received during the explicit key confirmation stage of the protocol,
 * <p>
 * Both {@link OwlClient} and {@link OwlServer} create and send an instance
 * of this payload to the other.
 * The payload to send should be created via
 * {@link OwlClient#initiateKeyConfirmation(BigInteger)}
 * or {@link OwlServer#initiateKeyConfirmation(BigInteger)}.
 * <p>
 * Both {@link OwlClient} and {@link OwlServer} must also validate the payload
 * received from the other.
 * The received payload should be validated via
 * {@link OwlClient#validateKeyConfirmation(OwlKeyConfirmation, BigInteger)}
 * {@link OwlServer#validateKeyConfirmation(OwlKeyConfirmation, BigInteger)}
 */
public class OwlKeyConfirmation
{

    /**
     * The id of either {@link OwlClient} or {@link OwlServer} who created/sent this payload.
     */
    private final String id;

    /**
     * The value of MacTag, as computed by the key confirmation round.
     *
     * @see OwlUtil#calculateMacTag
     */
    private final BigInteger macTag;

    /**
     * Constructor of OwlKeyConfirmation
     * @param id The identity of the sender
     * @param magTag The key confirmation string
     */
    public OwlKeyConfirmation(String id, BigInteger magTag)
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