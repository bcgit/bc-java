package org.bouncycastle.crypto.agreement.ecjpake;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Exceptions;

/**
 * A participant in a Password Authenticated Key Exchange by Juggling (J-PAKE) exchange.
 * <p>
 * The J-PAKE exchange is defined by Feng Hao and Peter Ryan in the paper
 * <a href="https://eprint.iacr.org/2010/190.pdf">
 * "J-PAKE: Authenticated Key Exchange Without PKI."</a>
 * <p>
 * The J-PAKE protocol is symmetric.
 * There is no notion of a <i>client</i> or <i>server</i>, but rather just two <i>participants</i>.
 * An instance of {@link ECJPAKEParticipant} represents one participant, and
 * is the primary interface for executing the exchange.
 * <p>
 * To execute an exchange, construct a {@link ECJPAKEParticipant} on each end,
 * and call the following 7 methods
 * (once and only once, in the given order, for each participant, sending messages between them as described):
 * <ol>
 * <li>{@link #createRound1PayloadToSend()} - and send the payload to the other participant</li>
 * <li>{@link #validateRound1PayloadReceived(ECJPAKERound1Payload)} - use the payload received from the other participant</li>
 * <li>{@link #createRound2PayloadToSend()} - and send the payload to the other participant</li>
 * <li>{@link #validateRound2PayloadReceived(ECJPAKERound2Payload)} - use the payload received from the other participant</li>
 * <li>{@link #calculateKeyingMaterial()}</li>
 * <li>{@link #createRound3PayloadToSend(BigInteger)} - and send the payload to the other participant</li>
 * <li>{@link #validateRound3PayloadReceived(ECJPAKERound3Payload, BigInteger)} - use the payload received from the other participant</li>
 * </ol>
 * <p>
 * Each side should derive a session key from the keying material returned by {@link #calculateKeyingMaterial()}.
 * The caller is responsible for deriving the session key using a secure key derivation function (KDF).
 * <p>
 * Round 3 is an optional key confirmation process.
 * If you do not execute round 3, then there is no assurance that both participants are using the same key.
 * (i.e. if the participants used different passwords, then their session keys will differ.)
 * <p>
 * If the round 3 validation succeeds, then the keys are guaranteed to be the same on both sides.
 * <p>
 * The symmetric design can easily support the asymmetric cases when one party initiates the communication.
 * e.g. Sometimes the round1 payload and round2 payload may be sent in one pass.
 * Also, in some cases, the key confirmation payload can be sent together with the round2 payload.
 * These are the trivial techniques to optimize the communication.
 * <p>
 * The key confirmation process is implemented as specified in
 * <a href="https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Ar3.pdf">NIST SP 800-56A Revision 3</a>,
 * Section 5.9.1 Unilateral Key Confirmation for Key Agreement Schemes.
 * <p>
 * This class is stateful and NOT threadsafe.
 * Each instance should only be used for ONE complete J-PAKE exchange
 * (i.e. a new {@link ECJPAKEParticipant} should be constructed for each new J-PAKE exchange).
 * <p>
 */
public class ECJPAKEParticipant
{

    /*
     * Possible internal states.  Used for state checking.
     */

    public static final int STATE_INITIALIZED = 0;
    public static final int STATE_ROUND_1_CREATED = 10;
    public static final int STATE_ROUND_1_VALIDATED = 20;
    public static final int STATE_ROUND_2_CREATED = 30;
    public static final int STATE_ROUND_2_VALIDATED = 40;
    public static final int STATE_KEY_CALCULATED = 50;
    public static final int STATE_ROUND_3_CREATED = 60;
    public static final int STATE_ROUND_3_VALIDATED = 70;

    /**
     * Unique identifier of this participant.
     * The two participants in the exchange must NOT share the same id.
     */
    private final String participantId;

    /**
     * Shared secret.  This only contains the secret between construction
     * and the call to {@link #calculateKeyingMaterial()}.
     * <p>
     * i.e. When {@link #calculateKeyingMaterial()} is called, this buffer overwritten with 0's,
     * and the field is set to null.
     * </p>
     */
    private char[] password;

    /**
     * Digest to use during calculations.
     */
    private final Digest digest;

    /**
     * Source of secure random data.
     */
    private final SecureRandom random;

    /**
     * The participantId of the other participant in this exchange.
     */
    private String partnerParticipantId;

    private ECCurve.AbstractFp ecCurve;
    private BigInteger q;
    private BigInteger h;
    private BigInteger n;
    private ECPoint g;

    /**
     * Alice's x1 or Bob's x3.
     */
    private BigInteger x1;
    /**
     * Alice's x2 or Bob's x4.
     */
    private BigInteger x2;
    /**
     * Alice's g^x1 or Bob's g^x3.
     */
    private ECPoint gx1;
    /**
     * Alice's g^x2 or Bob's g^x4.
     */
    private ECPoint gx2;
    /**
     * Alice's g^x3 or Bob's g^x1.
     */
    private ECPoint gx3;
    /**
     * Alice's g^x4 or Bob's g^x2.
     */
    private ECPoint gx4;
    /**
     * Alice's B or Bob's A.
     */
    private ECPoint b;

    /**
     * The current state.
     * See the <tt>STATE_*</tt> constants for possible values.
     */
    private int state;

    /**
     * Convenience constructor for a new {@link ECJPAKEParticipant} that uses
     * the {@link ECJPAKECurves#NIST_P256} elliptic curve,
     * a SHA-256 digest, and a default {@link SecureRandom} implementation.
     * <p>
     * After construction, the {@link #getState() state} will be  {@link #STATE_INITIALIZED}.
     *
     * @param participantId unique identifier of this participant.
     *                      The two participants in the exchange must NOT share the same id.
     * @param password      shared secret.
     *                      A defensive copy of this array is made (and cleared once {@link #calculateKeyingMaterial()} is called).
     *                      Caller should clear the input password as soon as possible.
     * @throws NullPointerException     if any argument is null
     * @throws IllegalArgumentException if password is empty
     */
    public ECJPAKEParticipant(
        String participantId,
        char[] password)
    {
        this(
            participantId,
            password,
            ECJPAKECurves.NIST_P256);
    }

    /**
     * Convenience constructor for a new {@link ECJPAKEParticipant} that uses
     * a SHA-256 digest and a default {@link SecureRandom} implementation.
     * <p>
     * After construction, the {@link #getState() state} will be  {@link #STATE_INITIALIZED}.
     *
     * @param participantId unique identifier of this participant.
     *                      The two participants in the exchange must NOT share the same id.
     * @param password      shared secret.
     *                      A defensive copy of this array is made (and cleared once {@link #calculateKeyingMaterial()} is called).
     *                      Caller should clear the input password as soon as possible.
     * @param curve         elliptic curve
     *                      See {@link ECJPAKECurves} for standard curves.
     * @throws NullPointerException     if any argument is null
     * @throws IllegalArgumentException if password is empty
     */
    public ECJPAKEParticipant(
        String participantId,
        char[] password,
        ECJPAKECurve curve)
    {
        this(
            participantId,
            password,
            curve,
            SHA256Digest.newInstance(),
            CryptoServicesRegistrar.getSecureRandom());
    }

    /**
     * Construct a new {@link ECJPAKEParticipant}.
     * <p>
     * After construction, the {@link #getState() state} will be  {@link #STATE_INITIALIZED}.
     *
     * @param participantId unique identifier of this participant.
     *                      The two participants in the exchange must NOT share the same id.
     * @param password      shared secret.
     *                      A defensive copy of this array is made (and cleared once {@link #calculateKeyingMaterial()} is called).
     *                      Caller should clear the input password as soon as possible.
     * @param curve         elliptic curve.
     *                      See {@link ECJPAKECurves} for standard curves
     * @param digest        digest to use during zero knowledge proofs and key confirmation (SHA-256 or stronger preferred)
     * @param random        source of secure random data for x1 and x2, and for the zero knowledge proofs
     * @throws NullPointerException     if any argument is null
     * @throws IllegalArgumentException if password is empty
     */
    public ECJPAKEParticipant(
        String participantId,
        char[] password,
        ECJPAKECurve curve,
        Digest digest,
        SecureRandom random)
    {
        ECJPAKEUtil.validateNotNull(participantId, "participantId");
        ECJPAKEUtil.validateNotNull(password, "password");
        ECJPAKEUtil.validateNotNull(curve, "curve params");
        ECJPAKEUtil.validateNotNull(digest, "digest");
        ECJPAKEUtil.validateNotNull(random, "random");
        if (password.length == 0)
        {
            throw new IllegalArgumentException("Password must not be empty.");
        }

        this.participantId = participantId;

        /*
         * Create a defensive copy so as to fully encapsulate the password.
         *
         * This array will contain the password for the lifetime of this
         * participant BEFORE {@link #calculateKeyingMaterial()} is called.
         *
         * i.e. When {@link #calculateKeyingMaterial()} is called, the array will be cleared
         * in order to remove the password from memory.
         *
         * The caller is responsible for clearing the original password array
         * given as input to this constructor.
         */
        this.password = Arrays.copyOf(password, password.length);

        this.ecCurve = curve.getCurve();
        this.g = curve.getG();
        this.h = curve.getH();
        this.n = curve.getN();
        this.q = curve.getQ();

        this.digest = digest;
        this.random = random;

        this.state = STATE_INITIALIZED;
    }

    /**
     * Gets the current state of this participant.
     * See the <tt>STATE_*</tt> constants for possible values.
     */
    public int getState()
    {
        return this.state;
    }

    /**
     * Creates and returns the payload to send to the other participant during round 1.
     * <p>
     * After execution, the {@link #getState() state} will be  {@link #STATE_ROUND_1_CREATED}.
     */
    public ECJPAKERound1Payload createRound1PayloadToSend()
    {
        if (this.state >= STATE_ROUND_1_CREATED)
        {
            throw new IllegalStateException("Round1 payload already created for " + participantId);
        }

        this.x1 = ECJPAKEUtil.generateX1(n, random);
        this.x2 = ECJPAKEUtil.generateX1(n, random);

        this.gx1 = ECJPAKEUtil.calculateGx(g, x1);
        this.gx2 = ECJPAKEUtil.calculateGx(g, x2);

        ECSchnorrZKP knowledgeProofForX1 = ECJPAKEUtil.calculateZeroKnowledgeProof(g, n, x1, gx1, digest, participantId, random);
        ECSchnorrZKP knowledgeProofForX2 = ECJPAKEUtil.calculateZeroKnowledgeProof(g, n, x2, gx2, digest, participantId, random);

        this.state = STATE_ROUND_1_CREATED;

        return new ECJPAKERound1Payload(participantId, gx1, gx2, knowledgeProofForX1, knowledgeProofForX2);
    }

    /**
     * Validates the payload received from the other participant during round 1.
     * <p>
     * Must be called prior to {@link #createRound2PayloadToSend()}.
     * <p>
     * After execution, the {@link #getState() state} will be  {@link #STATE_ROUND_1_VALIDATED}.
     *
     * @throws CryptoException       if validation fails.
     * @throws IllegalStateException if called multiple times.
     */
    public void validateRound1PayloadReceived(ECJPAKERound1Payload round1PayloadReceived)
        throws CryptoException
    {
        if (this.state >= STATE_ROUND_1_VALIDATED)
        {
            throw new IllegalStateException("Validation already attempted for round1 payload for" + participantId);
        }
        this.partnerParticipantId = round1PayloadReceived.getParticipantId();
        this.gx3 = round1PayloadReceived.getGx1();
        this.gx4 = round1PayloadReceived.getGx2();

        ECSchnorrZKP knowledgeProofForX3 = round1PayloadReceived.getKnowledgeProofForX1();
        ECSchnorrZKP knowledgeProofForX4 = round1PayloadReceived.getKnowledgeProofForX2();

        ECJPAKEUtil.validateParticipantIdsDiffer(participantId, round1PayloadReceived.getParticipantId());
        ECJPAKEUtil.validateZeroKnowledgeProof(g, gx3, knowledgeProofForX3, q, n, ecCurve, h, round1PayloadReceived.getParticipantId(), digest);
        ECJPAKEUtil.validateZeroKnowledgeProof(g, gx4, knowledgeProofForX4, q, n, ecCurve, h, round1PayloadReceived.getParticipantId(), digest);

        this.state = STATE_ROUND_1_VALIDATED;
    }

    /**
     * Creates and returns the payload to send to the other participant during round 2.
     * <p>
     * {@link #validateRound1PayloadReceived(ECJPAKERound1Payload)} must be called prior to this method.
     * <p>
     * After execution, the {@link #getState() state} will be  {@link #STATE_ROUND_2_CREATED}.
     *
     * @throws IllegalStateException if called prior to {@link #validateRound1PayloadReceived(ECJPAKERound1Payload)}, or multiple times
     */
    public ECJPAKERound2Payload createRound2PayloadToSend()
    {
        if (this.state >= STATE_ROUND_2_CREATED)
        {
            throw new IllegalStateException("Round2 payload already created for " + this.participantId);
        }
        if (this.state < STATE_ROUND_1_VALIDATED)
        {
            throw new IllegalStateException("Round1 payload must be validated prior to creating Round2 payload for " + this.participantId);
        }
        ECPoint gA = ECJPAKEUtil.calculateGA(gx1, gx3, gx4);
        BigInteger s = calculateS();
        BigInteger x2s = ECJPAKEUtil.calculateX2s(n, x2, s);
        ECPoint A = ECJPAKEUtil.calculateA(gA, x2s);
        ECSchnorrZKP knowledgeProofForX2s = ECJPAKEUtil.calculateZeroKnowledgeProof(gA, n, x2s, A, digest, participantId, random);

        this.state = STATE_ROUND_2_CREATED;

        return new ECJPAKERound2Payload(participantId, A, knowledgeProofForX2s);
    }

    /**
     * Validates the payload received from the other participant during round 2.
     * <p>
     * Note that this DOES NOT detect a non-common password.
     * The only indication of a non-common password is through derivation
     * of different keys (which can be detected explicitly by executing round 3 and round 4)
     * <p>
     * Must be called prior to {@link #calculateKeyingMaterial()}.
     * <p>
     * After execution, the {@link #getState() state} will be  {@link #STATE_ROUND_2_VALIDATED}.
     *
     * @throws CryptoException       if validation fails.
     * @throws IllegalStateException if called prior to {@link #validateRound1PayloadReceived(ECJPAKERound1Payload)}, or multiple times
     */
    public void validateRound2PayloadReceived(ECJPAKERound2Payload round2PayloadReceived)
        throws CryptoException
    {
        if (this.state >= STATE_ROUND_2_VALIDATED)
        {
            throw new IllegalStateException("Validation already attempted for round2 payload for" + participantId);
        }
        if (this.state < STATE_ROUND_1_VALIDATED)
        {
            throw new IllegalStateException("Round1 payload must be validated prior to validating Round2 payload for " + this.participantId);
        }
        ECPoint gB = ECJPAKEUtil.calculateGA(gx3, gx1, gx2);
        this.b = round2PayloadReceived.getA();
        ECSchnorrZKP knowledgeProofForX4s = round2PayloadReceived.getKnowledgeProofForX2s();

        ECJPAKEUtil.validateParticipantIdsDiffer(participantId, round2PayloadReceived.getParticipantId());
        ECJPAKEUtil.validateParticipantIdsEqual(this.partnerParticipantId, round2PayloadReceived.getParticipantId());
        ECJPAKEUtil.validateZeroKnowledgeProof(gB, b, knowledgeProofForX4s, q, n, ecCurve, h, round2PayloadReceived.getParticipantId(), digest);

        this.state = STATE_ROUND_2_VALIDATED;
    }

    /**
     * Calculates and returns the key material.
     * A session key must be derived from this key material using a secure key derivation function (KDF).
     * The KDF used to derive the key is handled externally (i.e. not by {@link ECJPAKEParticipant}).
     * <p>
     * The keying material will be identical for each participant if and only if
     * each participant's password is the same.  i.e. If the participants do not
     * share the same password, then each participant will derive a different key.
     * Therefore, if you immediately start using a key derived from
     * the keying material, then you must handle detection of incorrect keys.
     * If you want to handle this detection explicitly, you can optionally perform
     * rounds 3 and 4.  See {@link ECJPAKEParticipant} for details on how to execute
     * rounds 3 and 4.
     * <p>
     * The keying material will be in the range <tt>[0, n-1]</tt>.
     * <p>
     * {@link #validateRound2PayloadReceived(ECJPAKERound2Payload)} must be called prior to this method.
     * <p>
     * As a side effect, the internal {@link #password} array is cleared, since it is no longer needed.
     * <p>
     * After execution, the {@link #getState() state} will be  {@link #STATE_KEY_CALCULATED}.
     *
     * @throws IllegalStateException if called prior to {@link #validateRound2PayloadReceived(ECJPAKERound2Payload)},
     *                               or if called multiple times.
     */
    public BigInteger calculateKeyingMaterial()
    {
        if (this.state >= STATE_KEY_CALCULATED)
        {
            throw new IllegalStateException("Key already calculated for " + participantId);
        }
        if (this.state < STATE_ROUND_2_VALIDATED)
        {
            throw new IllegalStateException("Round2 payload must be validated prior to creating key for " + participantId);
        }
        BigInteger s = calculateS();

        /*
         * Clear the password array from memory, since we don't need it anymore.
         *
         * Also set the field to null as a flag to indicate that the key has already been calculated.
         */
        Arrays.fill(password, (char)0);
        this.password = null;

        BigInteger keyingMaterial = ECJPAKEUtil.calculateKeyingMaterial(n, gx4, x2, s, b);

        /*
         * Clear the ephemeral private key fields as well.
         * Note that we're relying on the garbage collector to do its job to clean these up.
         * The old objects will hang around in memory until the garbage collector destroys them.
         *
         * If the ephemeral private keys x1 and x2 are leaked,
         * the attacker might be able to brute-force the password.
         */
        this.x1 = null;
        this.x2 = null;
        this.b = null;

        /*
         * Do not clear gx* yet, since those are needed by round 3.
         */
        this.state = STATE_KEY_CALCULATED;

        return keyingMaterial;
    }

    /**
     * Creates and returns the payload to send to the other participant during round 3.
     * <p>
     * See {@link ECJPAKEParticipant} for more details on round 3.
     * <p>
     * After execution, the {@link #getState() state} will be  {@link #STATE_ROUND_3_CREATED}.
     *
     * @param keyingMaterial The keying material as returned from {@link #calculateKeyingMaterial()}.
     * @throws IllegalStateException if called prior to {@link #calculateKeyingMaterial()}, or multiple times
     */
    public ECJPAKERound3Payload createRound3PayloadToSend(BigInteger keyingMaterial)
    {
        if (this.state >= STATE_ROUND_3_CREATED)
        {
            throw new IllegalStateException("Round3 payload already created for " + this.participantId);
        }
        if (this.state < STATE_KEY_CALCULATED)
        {
            throw new IllegalStateException("Keying material must be calculated prior to creating Round3 payload for " + this.participantId);
        }

        BigInteger macTag = ECJPAKEUtil.calculateMacTag(
            this.participantId,
            this.partnerParticipantId,
            this.gx1,
            this.gx2,
            this.gx3,
            this.gx4,
            keyingMaterial,
            this.digest);

        this.state = STATE_ROUND_3_CREATED;

        return new ECJPAKERound3Payload(participantId, macTag);
    }

    /**
     * Validates the payload received from the other participant during round 3.
     * <p>
     * See {@link ECJPAKEParticipant} for more details on round 3.
     * <p>
     * After execution, the {@link #getState() state} will be {@link #STATE_ROUND_3_VALIDATED}.
     *
     * @param round3PayloadReceived The round 3 payload received from the other participant.
     * @param keyingMaterial        The keying material as returned from {@link #calculateKeyingMaterial()}.
     * @throws CryptoException       if validation fails.
     * @throws IllegalStateException if called prior to {@link #calculateKeyingMaterial()}, or multiple times
     */
    public void validateRound3PayloadReceived(ECJPAKERound3Payload round3PayloadReceived, BigInteger keyingMaterial)
        throws CryptoException
    {
        if (this.state >= STATE_ROUND_3_VALIDATED)
        {
            throw new IllegalStateException("Validation already attempted for round3 payload for" + participantId);
        }
        if (this.state < STATE_KEY_CALCULATED)
        {
            throw new IllegalStateException("Keying material must be calculated validated prior to validating Round3 payload for " + this.participantId);
        }
        ECJPAKEUtil.validateParticipantIdsDiffer(participantId, round3PayloadReceived.getParticipantId());
        ECJPAKEUtil.validateParticipantIdsEqual(this.partnerParticipantId, round3PayloadReceived.getParticipantId());

        ECJPAKEUtil.validateMacTag(
            this.participantId,
            this.partnerParticipantId,
            this.gx1,
            this.gx2,
            this.gx3,
            this.gx4,
            keyingMaterial,
            this.digest,
            round3PayloadReceived.getMacTag());


        /*
         * Clear the rest of the fields.
         */
        this.gx1 = null;
        this.gx2 = null;
        this.gx3 = null;
        this.gx4 = null;

        this.state = STATE_ROUND_3_VALIDATED;
    }

    private BigInteger calculateS()
    {
        try
        {
            return ECJPAKEUtil.calculateS(n, password);
        }
        catch (CryptoException e)
        {
            throw Exceptions.illegalStateException(e.getMessage(), e);
        }
    }

}
