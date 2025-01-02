package org.bouncycastle.crypto.agreement.ecjpake;

import org.bouncycastle.math.ec.ECPoint;

/**
 * The payload sent/received during the first round of a EC J-PAKE exchange.
 * <p>
 * Each {@link ECJPAKEParticipant} creates and sends an instance
 * of this payload to the other {@link ECJPAKEParticipant}.
 * The payload to send should be created via
 * {@link ECJPAKEParticipant#createRound1PayloadToSend()}.
 * <p>
 * Each {@link ECJPAKEParticipant} must also validate the payload
 * received from the other {@link ECJPAKEParticipant}.
 * The received payload should be validated via
 * {@link ECJPAKEParticipant#validateRound1PayloadReceived(ECJPAKERound1Payload)}.
 */
public class ECJPAKERound1Payload
{

    private final String participantId;

    /**
     * The value of g^x1
     */
    private final ECPoint gx1;

    /**
     * The value of g^x2
     */
    private final ECPoint gx2;

    /**
     * The zero knowledge proof for x1.
     * <p>
     * This is a class {@link ECSchnorrZKP} with two fields, containing {g^v, r} for x1.
     * </p>
     */
    private final ECSchnorrZKP knowledgeProofForX1;

    /**
     * The zero knowledge proof for x2.
     * <p>
     * This is a class {@link ECSchnorrZKP} with two fields, containing {g^v, r} for x2.
     * </p>
     */
    private final ECSchnorrZKP knowledgeProofForX2;

    public ECJPAKERound1Payload(
        String participantId,
        ECPoint gx1,
        ECPoint gx2,
        ECSchnorrZKP knowledgeProofForX1,
        ECSchnorrZKP knowledgeProofForX2)
    {
        ECJPAKEUtil.validateNotNull(participantId, "participantId");
        ECJPAKEUtil.validateNotNull(gx1, "gx1");
        ECJPAKEUtil.validateNotNull(gx2, "gx2");
        ECJPAKEUtil.validateNotNull(knowledgeProofForX1, "knowledgeProofForX1");
        ECJPAKEUtil.validateNotNull(knowledgeProofForX2, "knowledgeProofForX2");

        this.participantId = participantId;
        this.gx1 = gx1;
        this.gx2 = gx2;
        this.knowledgeProofForX1 = knowledgeProofForX1;
        this.knowledgeProofForX2 = knowledgeProofForX2;
    }

    public String getParticipantId()
    {
        return participantId;
    }

    public ECPoint getGx1()
    {
        return gx1;
    }

    public ECPoint getGx2()
    {
        return gx2;
    }

    public ECSchnorrZKP getKnowledgeProofForX1()
    {
        return knowledgeProofForX1;
    }

    public ECSchnorrZKP getKnowledgeProofForX2()
    {
        return knowledgeProofForX2;
    }

}