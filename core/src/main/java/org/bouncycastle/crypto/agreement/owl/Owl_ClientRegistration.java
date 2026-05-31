package org.example;

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
 * A client in the Owl key exchange protocol specifically for the user registration phase.
 * <p>
 * There is one client and one server communicating between each other.
 * An instance of {@link Owl_ServerRegistration} represents one server, and
 * an instance of {@link Owl_ClientRegistration} represents one client.
 * These together make up the main machine through which user registration is facilitated.
 * <p>
 * To execute the registration, construct an {@link Owl_ServerRegistration} on the server end,
 * and construct an {@link Owl_ClientRegistration} on the client end.
 * Each Owl registration will need a new and distinct {@link Owl_ServerRegistration} and {@link Owl_ClientRegistration}.
 * You cannot use the same {@link Owl_ServerRegistration} or {@link Owl_ClientRegistration} for multiple exchanges.
 * <p>
 * For user login go to {@link Owl_Client} and {@link Owl_Server}.
 * To execute the user registration phase, both
 * {@link Owl_ServerRegistration} and {@link Owl_ClientRegistration} must be constructed. 
 * <p>
 * The following communication between {@link Owl_ServerRegistration} and {@link Owl_ClientRegistration}, must be
 * facilitated over a secure communications channel as the leakage of the payload sent, 
 * would allow an attacker to reconstruct the secret password.
 * <p>
 * Call the following methods in this order, the client initiates every exchange.
 * <ul>
 * <li> {@link Owl_ClientRegistration#initiateUserRegistration()} - The client sends payload to the server over a secure channel. </li>
 * <li> {@link Owl_ServerRegistration#registerUseronServer(Owl_InitialRegistration)} - The server uses the payload received from the client to calculate a user credential payload that is to be safely stored on the server.</li>
 * </ul>
 * <p>
 * This class is stateful and NOT threadsafe.
 * Each instance should only be used for ONE complete Owl exchange
 * (i.e. a new {@link Owl_ServerRegistration} and {@link Owl_ClientRegistration} should be constructed for each new Owl exchange).
 */
public class Owl_ClientRegistration{
    /*
     * Possible state for user registration.
     */
    public static final boolean REGISTRATION_NOT_CALLED = false;
    public static final boolean REGISTRATION_CALLED = true;
    /**
     * Unique identifier of this client.
     * <p>
     * The client and server in the exchange must NOT share the same id.
     * </p>
     */
    private final String clientId;
    /**
     * Shared secret.  This only contains the secret between construction
     * and the call to {@link #initiateUserRegistration()}.
     * <p>
     * i.e. When {@link #initiateUserRegistration()} is called, this buffer is overwritten with 0's,
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
     * Client's user specified secret t = H(username||password) mod n
     */
    private BigInteger t;
    
    private BigInteger n;
    private ECPoint g;
    /**
     * Checks if user registration is called more than once.
     */
    private boolean registrationState;
    /**
     * Get the status of the user registration. 
     * I.E. whether or not this server has registered a user already.
     * See the <code>REGSITRATION_*</code> constants for possible values.
     * @return True if the user has been registered or false otherwise
     */
    public boolean getRegistrationState()
    {
        return this.registrationState;
    }

    /**
     * Convenience constructor for a new {@link Owl_ClientRegistration} that uses
     * the {@link Owl_Curves#NIST_P256} elliptic curve,
     * a SHA-256 digest, and a default {@link SecureRandom} implementation.
     * <p>
     * After construction, the {@link #getRegistrationState() state} will be  {@link #REGISTRATION_NOT_CALLED}.
     *
     * @param clientId unique identifier of this client.
     *                      The server and client in the exchange must NOT share the same id.
     * @param password      shared secret.
     *                      A defensive copy of this array is made (and cleared once {@link #initiateUserRegistration()} is called).
     *                      Caller should clear the input password as soon as possible.
     * @throws NullPointerException     if any argument is null
     * @throws IllegalArgumentException if password is empty
     */
    public Owl_ClientRegistration(
        String clientId,
        char[] password)
    {
        this(
            clientId,
            password,
            Owl_Curves.NIST_P256);
    }

    /**
     * Convenience constructor for a new {@link Owl_ClientRegistration} that uses
     * a SHA-256 digest and a default {@link SecureRandom} implementation.
     * <p>
     * After construction, the {@link #getRegistrationState() state} will be {@link #REGISTRATION_NOT_CALLED}.
     *
     * @param clientId unique identifier of this client..
     *                      The server and client in the exchange must NOT share the same id.     
     * @param password      shared secret.
     *                      A defensive copy of this array is made (and cleared once {@link #initiateUserRegistration()} is called).
     *                      Caller should clear the input password as soon as possible.
     * @param curve         elliptic curve
     *                      See {@link Owl_Curves} for standard curves.
     * @throws NullPointerException     if any argument is null
     * @throws IllegalArgumentException if password is empty
     */
    public Owl_ClientRegistration(
        String clientId,
        char[] password,
        Owl_Curve curve)
    {
        this(
            clientId,
            password,
            curve,
            SHA256Digest.newInstance(),
            CryptoServicesRegistrar.getSecureRandom());
    }

    /**
     * Construct a new {@link Owl_ClientRegistration}.
     * <p>
     * After construction, the {@link #getRegistrationState() registrationState} will be  {@link #REGISTRATION_NOT_CALLED}.
     *
     * @param clientId unique identifier of this client.
     *                      The server and client in the exchange must NOT share the same id.
     * @param password      shared secret.
     *                      A defensive copy of this array is made (and cleared once {@link #initiateUserRegistration()} is called).
     *                      Caller should clear the input password as soon as possible.
     * @param curve         elliptic curve.
     *                      See {@link Owl_Curves} for standard curves
     * @param digest        digest to use during zero knowledge proofs and key confirmation (SHA-256 or stronger preferred)
     * @param random        source of secure random data for x1 and x2, and for the zero knowledge proofs
     * @throws NullPointerException     if any argument is null
     * @throws IllegalArgumentException if password is empty
     */
    public Owl_ClientRegistration(
        String clientId,
        char[] password,
        Owl_Curve curve,
        Digest digest,
        SecureRandom random)
    {
        Owl_Util.validateNotNull(clientId, "clientId");
        Owl_Util.validateNotNull(password, "password");
        Owl_Util.validateNotNull(curve, "curve params");
        Owl_Util.validateNotNull(digest, "digest");
        Owl_Util.validateNotNull(random, "random");
        if (password.length == 0)
        {
            throw new IllegalArgumentException("Password must not be empty.");
        }

        this.clientId = clientId;

        /*
         * Create a defensive copy so as to fully encapsulate the password.
         *
         * This array will contain the password for the lifetime of this
         * client BEFORE {@link #initiateUserRegistration()} is called.
         *
         * i.e. When {@link #initiateUserRegistration()} is called, the array will be cleared
         * in order to remove the password from memory.
         *
         * The caller is responsible for clearing the original password array
         * given as input to this constructor.
         */
        this.password = Arrays.copyOf(password, password.length);
        this.g = curve.getG();
        this.n = curve.getN();

        this.digest = digest;
        this.random = random;

        this.registrationState = REGISTRATION_NOT_CALLED;
    }
    /**
     * Initiates user registration with the server. Creates the registration payload {@link Owl_InitialRegistration} and sends it to the server.
     * MUST be sent over a secure channel.
     * <p>
     * Must be called prior to {@link Owl_ServerRegistration#registerUseronServer(Owl_InitialRegistration)}
     * @return {@link Owl_InitialRegistration}
     * @throws IllegalStateException if this function is called more than once
     */
    public Owl_InitialRegistration initiateUserRegistration()
    {
        if(this.registrationState)
        {
            throw new IllegalStateException("User login registration already begun by "+ clientId);
        }
        this.t = calculateT();

        BigInteger pi = calculatePi();

        ECPoint gt = Owl_Util.calculateGx(g, t);

        /*
         * Clear the password array from memory, since we don't need it anymore.
         *
         * Also set the field to null as a flag to indicate that the key has already been calculated.
         */
        Arrays.fill(password, (char)0);
        this.password = null;
        this.t = null;
        this.registrationState = REGISTRATION_CALLED;

        return new Owl_InitialRegistration(clientId, pi, gt);
    }

    private BigInteger calculateT()
    {
        try 
        {
        	// t = H(username||password). Prepend each item with its byte length (int) to set clear boundary
            return Owl_Util.calculateT(n, 
            		String.valueOf(clientId.getBytes().length) + clientId + 
            		String.valueOf(password.length) + new String(password), digest);
        } 
        catch (CryptoException e)
        {
            throw Exceptions.illegalStateException(e.getMessage(), e);
        }
    }
    private BigInteger calculatePi()
    {
        try 
        {
            return Owl_Util.calculatePi(n, t, digest);
        }
        catch (CryptoException e)
        {
            throw Exceptions.illegalStateException(e.getMessage(), e);
        }
    }
}
