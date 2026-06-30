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
 * A server in the Owl key exchange protocol specifically for the user registration phase.
 * <p>
 * See {@link OwlClientRegistration} for more details on the user registration in Owl. 
 * <p>
 * This class is stateful and NOT threadsafe.
 * Each instance should only be used for ONE complete Owl registration phase
 * (i.e. a new {@link OwlServerRegistration} and {@link OwlClientRegistration} should be constructed for each new Owl exchange).
 */
public class OwlServerRegistration
{
   /*
     * Possible state for user registration.
     */
    public static final boolean REGISTRATION_NOT_CALLED = false;
    public static final boolean REGISTRATION_CALLED = true;
    /**
     * Unique identifier of this server.
     * The client and server in the exchange must NOT share the same id.
     */
    private final String serverId;
    /**
     * Digest to use during calculations.
     */
    private final Digest digest;

    /**
     * Source of secure random data.
     */
    private final SecureRandom random;
    
    private ECCurve.AbstractFp ecCurve;
    private BigInteger h;
    private BigInteger q;
    private BigInteger n;
    private ECPoint g;
    /**
     * Checks if user registration is called more than once.
     */
    private boolean registrationState;
    
    /**
     * Check's the status of the user registration
     * I.E. whether or not this server has registered a user already.
     * See the <code>REGSITRATION_*</code> constants for possible values.
     * @return true if the user has been registered or false otherwise
     */
    public boolean getRegistrationState()
    {
        return this.registrationState;
    }
    /**
     * Convenience constructor for a new {@link OwlServerRegistration} that uses
     * the {@link OwlCurves#NIST_P256} elliptic curve,
     * a SHA-256 digest, and a default {@link SecureRandom} implementation.
     * <p>
     * After construction, the {@link #getRegistrationState() registrationState} will be  {@link #REGISTRATION_NOT_CALLED}.
     *
     * @param serverId unique identifier of this server.
     *                      The server and client in the exchange must NOT share the same id.
     * @throws NullPointerException     if any argument is null
     */
    public OwlServerRegistration(
        String serverId)
    {
        this(
            serverId,
            OwlCurves.NIST_P256);
    }

    /**
     * Convenience constructor for a new {@link OwlServerRegistration} that uses
     * a SHA-256 digest and a default {@link SecureRandom} implementation.
     * <p>
     * After construction, the {@link #getRegistrationState() registrationState} will be  {@link #REGISTRATION_NOT_CALLED}.
     *
     * @param serverId unique identifier of this server.
     *                      The server and client in the exchange must NOT share the same id.
     * @param curve         elliptic curve
     *                      See {@link OwlCurves} for standard curves.
     * @throws NullPointerException     if any argument is null
     */
    public OwlServerRegistration(
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
     * Construct a new {@link OwlServerRegistration}.
     * <p>
     * After construction, the {@link #getRegistrationState() registrationState} will be  {@link #REGISTRATION_NOT_CALLED}.
     *
     * @param serverId unique identifier of this server.
     *                      The client and server in the exchange must NOT share the same id.
     * @param curve         elliptic curve; see {@link OwlCurves} for standard curves
     * @param digest        digest to use during zero knowledge proofs and key confirmation (SHA-256 or stronger preferred)
     * @param random        source of secure random data for x3 and x4, and for the zero knowledge proofs
     * @throws NullPointerException     if any argument is null
     */
    public OwlServerRegistration(
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
        this.q = curve.getQ();
        this.h = curve.getH();
        this.g = curve.getG();
        this.n = curve.getN();

        this.digest = digest;
        this.random = random;

        this.registrationState = REGISTRATION_NOT_CALLED;
    }
    /**
     * Initiates user registration with the server. Creates the registration payload {@link OwlInitialRegistration} and sends it to the server.
     * MUST be sent over a secure channel.
     * <p>
     * Must be called prior to {@link #registerUseronServer(OwlInitialRegistration)}
     * @throws IllegalStateException if this function is called more than once
     */

    /**
     * Receives the payload sent by the client as part of user registration, and stores necessary values in the server.
     * <p>
     * Must be called after {@link OwlClientRegistration#initiateUserRegistration()} by the {@link OwlClient}.
     * @param userLoginRegistrationReceived {@link OwlInitialRegistration}
     * @return {@link OwlFinishRegistration}
     * @throws IllegalStateException if this functions is called more than once.
     * @throws CryptoException if validation of the payload fails
     */    
    public OwlFinishRegistration registerUseronServer(
        OwlInitialRegistration userLoginRegistrationReceived
        )
    throws CryptoException
    {
        if(this.registrationState)
        {
            throw new IllegalStateException("Server has already registrered this payload, by "+ serverId);
        }
        BigInteger x3 = OwlUtil.generateX1(n, random);

        ECPoint gx3 = OwlUtil.calculateGx(g, x3);

        ECSchnorrZKP knowledgeProofForX3 = OwlUtil.calculateZeroknowledgeProof(g, n, x3, gx3, digest, serverId, random);

        String clientId = userLoginRegistrationReceived.getClientId();
        BigInteger pi = userLoginRegistrationReceived.getPi();
        ECPoint gt = userLoginRegistrationReceived.getGt();

        OwlUtil.validateParticipantIdsDiffer(clientId, serverId);
        if (pi.compareTo(BigInteger.ONE) == -1 || pi.compareTo(n.subtract(BigInteger.ONE)) == 1)
        {
            throw new CryptoException("pi is not in the range of [1, n-1]. for " + serverId);
        }
        OwlUtil.validatePublicKey(gt, ecCurve, q, h);
        this.registrationState = REGISTRATION_CALLED;

        return new OwlFinishRegistration(clientId, knowledgeProofForX3, gx3, pi, gt); 
    }
}