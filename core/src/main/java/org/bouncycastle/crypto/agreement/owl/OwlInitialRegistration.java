package org.bouncycastle.crypto.agreement.owl;

import java.math.BigInteger;

import org.bouncycastle.math.ec.ECPoint;

/**
 * The payload sent by {@link OwlClientRegistration}, during the user registration phase of an Owl exchange.
 * <p>
 * The {@link OwlClientRegistration} creates and sends an instance
 * of this payload to the {@link OwlServerRegistration}.
 * The payload to send should be created via
 * {@link OwlClientRegistration#initiateUserRegistration()}.
 * <p>
 * Each {@link OwlServerRegistration} must also validate the payload
 * received from the {@link OwlClientRegistration}.
 * The received payload should be validated via
 * {@link OwlServerRegistration#registerUseronServer(OwlInitialRegistration)}.
 */
public class OwlInitialRegistration
{
    /**
     * Unique identifier for the client (same as username).
     * <p>
     * Must not be the same as the unique identifier for the server.
     * </p>
     */
    private final String clientId;
    /**
     * The value of pi = H(t), where t = H(Username||password) mod n
     */
    private final BigInteger pi;
    /**
     * The value of T = t * [G]
     */
    private final ECPoint gt;

    /**
     * Constructor of OwlInitialRegistration
     * @param clientId Client identity (or username)
     * @param pi pi = H(t), where t = H(Username||password) mod(n)
     * @param gt T = t * [G]
     */
    public OwlInitialRegistration(
        String clientId,
        BigInteger pi,
        ECPoint gt)
    {
        OwlUtil.validateNotNull(clientId, "clientId");
        OwlUtil.validateNotNull(pi, "pi");
        OwlUtil.validateNotNull(gt, "gt");

        this.clientId = clientId;
        this.pi = pi;
        this.gt = gt;
    }

    /**
     * Get the client identity (or username)
     * @return The client identity
     */
    public String getClientId()
    {
        return clientId;
    }

    /**
     * Get pi = H(t), where t = H(Username||password) mod(n)
     * @return pi
     */
    public BigInteger getPi()
    {
        return pi;
    }

    /**
     * Get T = t * [G]
     * @return T
     */
    public ECPoint getGt()
    {
        return gt;
    }
}