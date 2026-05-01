package org.bouncycastle.crypto.agreement.ecjpake;

import org.bouncycastle.math.ec.ECPoint;

/**
 * The payload sent/received during the second round of a EC J-PAKE exchange.
 * <p>
 * Each {@link ECJPAKEParticipant} creates and sends an instance
 * of this payload to the other {@link ECJPAKEParticipant}.
 * The payload to send should be created via
 * {@link ECJPAKEParticipant#createRound2PayloadToSend()}
 * <p>
 * Each {@link ECJPAKEParticipant} must also validate the payload
 * received from the other {@link ECJPAKEParticipant}.
 * The received payload should be validated via
 * {@link ECJPAKEParticipant#validateRound2PayloadReceived(ECJPAKERound2Payload)}
 */
public class ECJPAKERound2Payload
{

    /**
     * The id of the {@link ECJPAKEParticipant} who created/sent this payload.
     */
    private final String participantId;

    /**
     * The value of A, as computed during round 2.
     */
    private final ECPoint a;

    /**
     * The zero knowledge proof for x2 * s.
     * <p>
     * This is a class {@link ECSchnorrZKP} with two fields, containing {g^v, r} for x2 * s.
     * </p>
     */
    private final ECSchnorrZKP knowledgeProofForX2s;

    public ECJPAKERound2Payload(
        String participantId,
        ECPoint a,
        ECSchnorrZKP knowledgeProofForX2s)
    {
        ECJPAKEUtil.validateNotNull(participantId, "participantId");
        ECJPAKEUtil.validateNotNull(a, "a");
        ECJPAKEUtil.validateNotNull(knowledgeProofForX2s, "knowledgeProofForX2s");

        this.participantId = participantId;
        this.a = a;
        this.knowledgeProofForX2s = knowledgeProofForX2s;
    }

    public String getParticipantId()
    {
        return participantId;
    }

    public ECPoint getA()
    {
        return a;
    }

    public ECSchnorrZKP getKnowledgeProofForX2s()
    {
        return knowledgeProofForX2s;
    }

}
