package org.bouncycastle.crypto.agreement.owl;

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
 * A server in the Elliptic Curve Owl key exchange protocol.
 * <p>
 * See {@link OwlClient} for more details about Owl.
 */ 
public class OwlServer
{

    /*
     * Possible internal states.  Used for state checking.
     */
    public static final int STATE_INITIALISED = 0;
    public static final int STATE_LOGIN_INITIALISED = 10;
    public static final int STATE_LOGIN_FINISHED = 20;
    public static final int STATE_KEY_CALCULATED = 30;
    public static final int STATE_KC_INITIALISED = 40;
    public static final int STATE_KC_VALIDATED = 50;

    /**
     * Unique identifier of this server.
     * The client and server in the exchange must NOT share the same id.
     */
    private final String serverId;

    /**
     * Unique identifier for the client in the exchange.
     */
    private String clientId;

    /**
     * Digest to use during calculations.
     */
    private final Digest digest;

    /**
     * Source of secure random data.
     */
    private final SecureRandom random;

    private ECCurve.AbstractFp ecCurve;
    private BigInteger q;
    private BigInteger h;
    private BigInteger n;
    private ECPoint g;

    /**
     * Server's x4.
     */
    private BigInteger x4;
    /**
     * Client's gx1.
     */
    private ECPoint gx1;
    /**
     * Client's gx2.
     */
    private ECPoint gx2;
    /**
     * Server's gx3.
     */
    private ECPoint gx3;
    /**
     * Server's gx4.
     */
    private ECPoint gx4;
    /**
     * Shared secret used for authentication pi = H(t) mod n
     */
    private BigInteger pi;
    /**
     * Client's T, Password verifier stored on server
     */
    private ECPoint gt;
    /**
     * Server's beta value used in login authentication
     */
    private ECPoint beta;
    /**
     * ECSchnorrZKP knowledge proof for x1, using {@link ECSchnorrZKP}
     */
    private ECSchnorrZKP knowledgeProofForX1;
    /**
     * ECSchnorrZKP knowledge proof for x2, using {@link ECSchnorrZKP}
     */
    private ECSchnorrZKP knowledgeProofForX2;
    /**
     * ECSchnorrZKP knowledge proof for x3, using {@link ECSchnorrZKP}
     */
    private ECSchnorrZKP knowledgeProofForX3;
    /**
     * ECSchnorrZKP knowledge proof for x4, using {@link ECSchnorrZKP}
     */
    private ECSchnorrZKP knowledgeProofForX4;
    /**
     * ECSchnorrZKP knowledge proof for beta, using {@link ECSchnorrZKP}
     */
    private ECSchnorrZKP knowledgeProofForBeta;
    /**
     *  The raw key K used to calculate a session key.
     */
    private ECPoint rawKey;
    /**
     * The current state.
     * See the {@code STATE_*} constants for possible values.
     */
    private int state;

    /**
     * Convenience constructor for a new {@link OwlServer} that uses
     * the {@link OwlCurves#NIST_P256} elliptic curve,
     * a SHA-256 digest, and a default {@link SecureRandom} implementation.
     * <p>
     * After construction, the {@link #getState() state} will be {@link #STATE_INITIALISED}.
     *
     * @param serverId unique identifier of this server.
     *                      The server and client in the exchange must NOT share the same id.
     * @throws NullPointerException     if any argument is null
     */
    public OwlServer(
        String serverId)
    {
        this(
            serverId,
            OwlCurves.NIST_P256);
    }

    /**
     * Convenience constructor for a new {@link OwlServer} that uses
     * a SHA-256 digest and a default {@link SecureRandom} implementation.
     * <p>
     * After construction, the {@link #getState() state} will be {@link #STATE_INITIALISED}.
     *
     * @param serverId unique identifier of this server.
     *                      The server and client in the exchange must NOT share the same id.
     * @param curve         elliptic curve
     *                      See {@link OwlCurves} for standard curves.
     * @throws NullPointerException     if any argument is null
     */
    public OwlServer(
        String serverId,
        OwlCurve curve)
    {
        this(
            serverId,
            curve,
            SHA256Digest.newInstance(),
            CryptoServicesRegistrar.getSecureRandom());
    }

    /**
     * Construct a new {@link OwlServer}.
     * <p>
     * After construction, the {@link #getState() state} will be {@link #STATE_INITIALISED}.
     *
     * @param serverId unique identifier of this server.
     *                      The client and server in the exchange must NOT share the same id.
     * @param curve         elliptic curve
     *                      See {@link OwlCurves} for standard curves
     * @param digest        digest to use during zero knowledge proofs and key confirmation (SHA-256 or stronger preferred)
     * @param random        source of secure random data for x3 and x4, and for the zero knowledge proofs
     * @throws NullPointerException     if any argument is null
     */
    public OwlServer(
        String serverId,
        OwlCurve curve,
        Digest digest,
        SecureRandom random)
    {
        OwlUtil.validateNotNull(serverId, "serverId");
        OwlUtil.validateNotNull(curve, "curve params");
        OwlUtil.validateNotNull(digest, "digest");
        OwlUtil.validateNotNull(random, "random");

        this.serverId = serverId;

        this.ecCurve = curve.getCurve();
        this.g = curve.getG();
        this.h = curve.getH();
        this.n = curve.getN();
        this.q = curve.getQ();

        this.digest = digest;
        this.random = random;

        this.state = STATE_INITIALISED;
    }

    /**
     * Gets the current state of this server.
     * See the <code>STATE_*</code> constants for possible values.
     * 
     * @return The state of the server
     */
    public int getState()
    {
        return this.state;
    }

    /**
     * Validates the payload sent by {@link OwlClient#authenticationInitiate()} by {@link OwlClient}, and then creates a new {@link OwlAuthenticationServerResponse} payload and sends it to the {@link OwlClient}.
     * <p>
     * Must be called prior to {@link #authenticationServerEnd(OwlAuthenticationFinish)}.
     * <p>
     * After execution, the {@link #getState() state} will be {@link #STATE_LOGIN_INITIALISED}.
     *
     * @param authenticationInitiate    payload sent by {@link OwlClient#authenticationInitiate()} to be validated and used for further calculation.
     * @param userLoginCredentials      comes from the server where it stored the user login credentials as part of the user login registration.
     * @return {@link OwlAuthenticationServerResponse}
     * @throws CryptoException          if validation fails.
     * @throws IllegalStateException    if called multiple times.
     */
    public OwlAuthenticationServerResponse authenticationServerResponse(
        OwlAuthenticationInitiate authenticationInitiate, 
        OwlFinishRegistration userLoginCredentials)
        throws CryptoException
    {
        if (this.state >= STATE_LOGIN_INITIALISED)
        {
            throw new IllegalStateException("Response to client authentication initiation already created by " + serverId);
        }
        this.clientId = authenticationInitiate.getClientId();
        this.gx1 = authenticationInitiate.getGx1();
        this.gx2 = authenticationInitiate.getGx2();

        this.knowledgeProofForX1 = authenticationInitiate.getKnowledgeProofForX1();
        this.knowledgeProofForX2 = authenticationInitiate.getKnowledgeProofForX2();

        OwlUtil.validateParticipantIdsDiffer(serverId, authenticationInitiate.getClientId());
        OwlUtil.validateZeroknowledgeProof(g, gx1, knowledgeProofForX1, q, n, ecCurve, h, authenticationInitiate.getClientId(), digest);
        OwlUtil.validateZeroknowledgeProof(g, gx2, knowledgeProofForX2, q, n, ecCurve, h, authenticationInitiate.getClientId(), digest);

        this.x4 = OwlUtil.generateX1(n, random);

        this.gx4 = OwlUtil.calculateGx(g, x4);

        this.knowledgeProofForX4 = OwlUtil.calculateZeroknowledgeProof(g, n, x4, gx4, digest, serverId, random);

        this.gx3 = userLoginCredentials.getGx3();
        this.pi  = userLoginCredentials.getPi();
        this.knowledgeProofForX3 = userLoginCredentials.getKnowledgeProofForX3();
        this.gt = userLoginCredentials.getGt();

        OwlUtil.validateParticipantIdsEqual(this.clientId, userLoginCredentials.getClientId());

        ECPoint betaG = OwlUtil.calculateGA(gx1, gx2, gx3);
        BigInteger x4pi = OwlUtil.calculateX2s(n, x4, pi);
        this.beta = OwlUtil.calculateA(betaG, x4pi);
        this.knowledgeProofForBeta = OwlUtil.calculateZeroknowledgeProof(betaG, n, x4pi, beta, digest, serverId, random);

        this.state = STATE_LOGIN_INITIALISED;

        return new OwlAuthenticationServerResponse(serverId, gx3, gx4, knowledgeProofForX3, knowledgeProofForX4, beta, knowledgeProofForBeta);
    }

    /**
     * Validates the payload received from the client during the third pass of the Owl protocol.
     * Must be called prior to {@link #calculateKeyingMaterial()}.
     * <p>
     * After execution, the {@link #getState() state} will be {@link #STATE_LOGIN_FINISHED}.
     * 
     * @param authenticationFinish      payload sent by {@link OwlClient#authenticationFinish(OwlAuthenticationServerResponse)} to be validated.
     *
     * @throws CryptoException          if validation fails.
     * @throws IllegalStateException    if called prior to {@link #authenticationServerResponse(OwlAuthenticationInitiate, OwlFinishRegistration)}, or multiple times
     */
    public void authenticationServerEnd(OwlAuthenticationFinish authenticationFinish)
        throws CryptoException
    {
        if (this.state >= STATE_LOGIN_FINISHED)
        {
            throw new IllegalStateException("Server's authentication ending already called by " + serverId);
        }
        if (this.state < STATE_LOGIN_INITIALISED)
        {
            throw new IllegalStateException("Authentication server response required before authentication finish by " + this.serverId);
        }

        ECPoint alpha =  authenticationFinish.getAlpha();
        ECPoint alphaG = OwlUtil.calculateGA(gx1, gx3, gx4);
        ECSchnorrZKP knowledgeProofForAlpha = authenticationFinish.getKnowledgeProofForAlpha();
        
        OwlUtil.validateZeroknowledgeProof(alphaG, alpha, knowledgeProofForAlpha, q, n, ecCurve, h, clientId, digest);

        BigInteger x4pi = OwlUtil.calculateX2s(n, x4, pi);
        this.rawKey = OwlUtil.calculateKeyingMaterial(gx2, x4, x4pi, alpha);

        BigInteger hTranscript = OwlUtil.calculateTranscript(rawKey, clientId, gx1, gx2, knowledgeProofForX1, knowledgeProofForX2, serverId, gx3, gx4, 
            knowledgeProofForX3, knowledgeProofForX4, beta, knowledgeProofForBeta, alpha, knowledgeProofForAlpha, digest);

        OwlUtil.validateR(authenticationFinish.getR(), gx1, hTranscript, gt, g, n);
        OwlUtil.validateParticipantIdsDiffer(serverId, authenticationFinish.getClientId());
        OwlUtil.validateParticipantIdsEqual(this.clientId, authenticationFinish.getClientId());

        this.state = STATE_LOGIN_FINISHED;
    }

    /**
     * Calculates and returns the key material.
     * A session key must be derived from this key material using a secure key derivation function (KDF).
     * The KDF used to derive the key is handled externally (i.e. not by {@link OwlServer}).
     * <p>
     * The keying material will be identical for client and server if and only if
     * the login password is the same as the password stored by the server.  i.e. If the client and  
     * server do not share the same password, then each  will derive a different key.
     * Rememeber, the server does not explicitly hold the password, but a secret value derived from the password
     * sent to the server by the client during user registration.
     * Therefore, if you immediately start using a key derived from
     * the keying material, then you must handle detection of incorrect keys.
     * Validation of the r value also detects if passwords are different between user registration and user login.
     * If you want to check the equality of the key materials derived at the two sides explicitly, you can perform explicit
     * key confirmation.  See {@link OwlServer} for details on how to execute
     * key confirmation.
     * <p>
     * {@link #authenticationServerEnd(OwlAuthenticationFinish)} must be called prior to this method.
     * <p>
     * After execution, the {@link #getState() state} will be  {@link #STATE_KEY_CALCULATED}.
     *
     * @return The raw key material produced by the Owl key exchange process
     * @throws IllegalStateException if called prior to {@link #authenticationServerEnd(OwlAuthenticationFinish)},
     *                               or if called multiple times.
     */
    public BigInteger calculateKeyingMaterial()
    {
        if (this.state >= STATE_KEY_CALCULATED)
        {
            throw new IllegalStateException("Key already calculated for " + serverId);
        }
        if (this.state < STATE_LOGIN_FINISHED)
        {
            throw new IllegalStateException("Server must validate client's final payload prior to creating key for " + serverId);
        }

        BigInteger keyingMaterial = rawKey.normalize().getAffineXCoord().toBigInteger();
        /*
         * Clear the ephemeral private key fields as well.
         * Note that we're relying on the garbage collector to do its job to clean these up.
         * The old objects will hang around in memory until the garbage collector destroys them.
         *
         * If the ephemeral private key x4 are leaked,
         * the attacker might be able to brute-force the password.
         */
        this.x4 = null;
        this.beta = null;
        this.gt = null;
        this.rawKey = null;

        /*
         * Do not clear gx* yet, since those are needed by key confirmation.
         */
        this.state = STATE_KEY_CALCULATED;

        return keyingMaterial;
    }

    /**
     * Creates and returns the payload to send to the client as part of Key Confirmation.
     * <p>
     * See {@link OwlClient} for more details on Key Confirmation.
     * <p>
     * After execution, the {@link #getState() state} will be  {@link #STATE_KC_INITIALISED}.
     *
     * @param keyingMaterial The keying material as returned from {@link #calculateKeyingMaterial()}.
     * @return {@link OwlKeyConfirmation}
     * @throws IllegalStateException if called prior to {@link #calculateKeyingMaterial()}, or multiple times
     */
    public OwlKeyConfirmation initiateKeyConfirmation(BigInteger keyingMaterial)
    {
        if (this.state >= STATE_KC_INITIALISED)
        {
            throw new IllegalStateException("Key confirmation payload already created for " + this.serverId);
        }
        if (this.state < STATE_KEY_CALCULATED)
        {
            throw new IllegalStateException("Keying material must be calculated prior to creating key confirmation payload for " + this.serverId);
        }

        BigInteger macTag = OwlUtil.calculateMacTag(
            this.serverId,
            this.clientId,
            this.gx3,
            this.gx4,
            this.gx1,
            this.gx2,
            keyingMaterial,
            this.digest);

        this.state = STATE_KC_INITIALISED;

        return new OwlKeyConfirmation(serverId, macTag);
    }

    /**
     * Validates the payload received from the client as part of Key Confirmation.
     * <p>
     * See {@link OwlClient} for more details on Key Confirmation.
     * <p>
     * After execution, the {@link #getState() state} will be {@link #STATE_KC_VALIDATED}.
     *
     * @param keyConfirmationPayload The key confirmation payload received from the client..
     * @param keyingMaterial        The keying material as returned from {@link #calculateKeyingMaterial()}.
     * @throws CryptoException       if validation fails.
     * @throws IllegalStateException if called prior to {@link #calculateKeyingMaterial()}, or multiple times
     */
    public void validateKeyConfirmation(OwlKeyConfirmation keyConfirmationPayload, BigInteger keyingMaterial)
        throws CryptoException
    {
        if (this.state >= STATE_KC_VALIDATED)
        {
            throw new IllegalStateException("Validation already attempted for key confirmation payload by " + serverId);
        }
        if (this.state < STATE_KEY_CALCULATED)
        {
            throw new IllegalStateException("Keying material must be calculated validated prior to validating key confirmation payload for " + this.serverId);
        }
        OwlUtil.validateParticipantIdsDiffer(serverId, keyConfirmationPayload.getId());
        OwlUtil.validateParticipantIdsEqual(this.clientId, keyConfirmationPayload.getId());

        OwlUtil.validateMacTag(
            this.serverId,
            this.clientId,
            this.gx3,
            this.gx4,
            this.gx1,
            this.gx2,
            keyingMaterial,
            this.digest,
            keyConfirmationPayload.getMacTag());

        /*
         * Clear the rest of the fields.
         */
        this.gx1 = null;
        this.gx2 = null;
        this.gx3 = null;
        this.gx4 = null;

        this.state = STATE_KC_VALIDATED;
    }
}
