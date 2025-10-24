package org.example;

import java.math.BigInteger;

import org.bouncycastle.math.ec.ECPoint;

/**
 * The payload sent by {@link Owl_ClientRegistration}, during the user registration phase of an Owl exchange.
 * <p>
 * The {@link Owl_ClientRegistration} creates and sends an instance
 * of this payload to the {@link Owl_ServerRegistration}.
 * The payload to send should be created via
 * {@link Owl_ClientRegistration#initiateUserRegistration()}.
 * <p>
 * Each {@link Owl_ServerRegistration} must also validate the payload
 * received from the {@link Owl_ClientRegistration}.
 * The received payload should be validated via
 * {@link Owl_ServerRegistration#registerUseronServer(Owl_InitialRegistration)}.
 */
public class Owl_InitialRegistration
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
     * Constructor of Owl_InitialRegistration
     * @param clientId Client identity (or username)
     * @param pi pi = H(t), where t = H(Username||password) mod(n)
     * @param gt T = t * [G]
     */
    public Owl_InitialRegistration(
        String clientId,
        BigInteger pi,
        ECPoint gt)
    {
        Owl_Util.validateNotNull(clientId, "clientId");
        Owl_Util.validateNotNull(pi, "pi");
        Owl_Util.validateNotNull(gt, "gt");

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