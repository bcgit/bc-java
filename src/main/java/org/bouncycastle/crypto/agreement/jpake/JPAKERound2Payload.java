package org.bouncycastle.crypto.agreement.jpake;

import java.io.Serializable;
import java.math.BigInteger;

import org.bouncycastle.util.Arrays;

/**
 * The payload sent/received during the second round of a J-PAKE exchange.
 * <p/>
 * <p/>
 * Each {@link JPAKEParticipant} creates and sends an instance
 * of this payload to the other {@link JPAKEParticipant}.
 * The payload to send should be created via
 * {@link JPAKEParticipant#createRound2PayloadToSend()}
 * <p/>
 * <p/>
 * Each {@link JPAKEParticipant} must also validate the payload
 * received from the other {@link JPAKEParticipant}.
 * The received payload should be validated via
 * {@link JPAKEParticipant#validateRound2PayloadReceived(JPAKERound2Payload)}
 * <p/>
 * <p/>
 * This class is {@link Serializable}, so you can send it via Java serialization.
 * However, no specific mechanism for sending this payload to the other participant
 * is required.  It is perfectly safe to decompose the fields of this payload,
 * send those fields to the other participant in any format,
 * and reconstruct the payload on the other side using
 * {@link #JPAKERound2Payload(String, BigInteger, BigInteger[])}.
 */
public class JPAKERound2Payload
    implements Serializable
{
    private static final long serialVersionUID = 1L;

    /**
     * The id of the {@link JPAKEParticipant} who created/sent this payload.
     */
    private final String participantId;

    /**
     * The value of A, as computed during round 2.
     */
    private final BigInteger a;

    /**
     * The zero knowledge proof for x2 * s.
     * <p/>
     * This is a two element array, containing {g^v, r} for x2 * s.
     */
    private final BigInteger[] knowledgeProofForX2s;

    public JPAKERound2Payload(
        String participantId,
        BigInteger a,
        BigInteger[] knowledgeProofForX2s)
    {
        JPAKEUtil.validateNotNull(participantId, "participantId");
        JPAKEUtil.validateNotNull(a, "a");
        JPAKEUtil.validateNotNull(knowledgeProofForX2s, "knowledgeProofForX2s");

        this.participantId = participantId;
        this.a = a;
        this.knowledgeProofForX2s = Arrays.copyOf(knowledgeProofForX2s, knowledgeProofForX2s.length);
    }

    public String getParticipantId()
    {
        return participantId;
    }

    public BigInteger getA()
    {
        return a;
    }

    public BigInteger[] getKnowledgeProofForX2s()
    {
        return Arrays.copyOf(knowledgeProofForX2s, knowledgeProofForX2s.length);
    }

}
