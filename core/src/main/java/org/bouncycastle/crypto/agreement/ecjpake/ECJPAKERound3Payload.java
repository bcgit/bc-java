package org.bouncycastle.crypto.agreement.ecjpake;

import java.math.BigInteger;

/**
 * The payload sent/received during the optional third round of a EC J-PAKE exchange,
 * which is for explicit key confirmation.
 * <p>
 * Each {@link ECJPAKEParticipant} creates and sends an instance
 * of this payload to the other {@link ECJPAKEParticipant}.
 * The payload to send should be created via
 * {@link ECJPAKEParticipant#createRound3PayloadToSend(BigInteger)}
 * <p>
 * Each {@link ECJPAKEParticipant} must also validate the payload
 * received from the other {@link ECJPAKEParticipant}.
 * The received payload should be validated via
 * {@link ECJPAKEParticipant#validateRound3PayloadReceived(ECJPAKERound3Payload, BigInteger)}
 */
public class ECJPAKERound3Payload
{

    /**
     * The id of the {@link ECJPAKEParticipant} who created/sent this payload.
     */
    private final String participantId;

    /**
     * The value of MacTag, as computed by round 3.
     *
     * @see ECJPAKEUtil#calculateMacTag
     */
    private final BigInteger macTag;

    public ECJPAKERound3Payload(String participantId, BigInteger magTag)
    {
        this.participantId = participantId;
        this.macTag = magTag;
    }

    public String getParticipantId()
    {
        return participantId;
    }

    public BigInteger getMacTag()
    {
        return macTag;
    }

}