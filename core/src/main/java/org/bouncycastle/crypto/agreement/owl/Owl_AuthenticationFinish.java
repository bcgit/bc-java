package org.example;

import java.math.BigInteger;

import org.bouncycastle.math.ec.ECPoint;

/**
 * The payload sent by the client during the third pass of an Owl exchange.
 * <p>
 * Each {@link Owl_Client} creates and sends an instance
 * of this payload to the {@link Owl_Server} after validating the previous payload
 * {@link Owl_AuthenticationServerResponse}.
 * The payload to send should be created via
 * {@link Owl_Client#authenticationFinish(Owl_AuthenticationServerResponse)}.
 * <p>
 * Each {@link Owl_Client} must also validate the payload
 * received from the {@link Owl_Server}, which is done by the same function
 * {@link Owl_Client#authenticationFinish(Owl_AuthenticationServerResponse)}.
 */
public class Owl_AuthenticationFinish
{
    /**
     *  Client's unique Id
     */
    private final String clientId;
    /**
     * The value alpha = (x2 x pi) * [X1 + X3 + X4].
     */
    private final ECPoint alpha;

    /**
     * The zero Knowledge proof for alpha.
     * <p>
     * This is a class {@link ECSchnorrZKP} with two fields, containing {v * [G], r} for x2pi.
     * </p>
     */
    private final ECSchnorrZKP knowledgeProofForAlpha;

    /**
     * The value of r = x1 - t.h mod n
     */
    private final BigInteger r;

    /**
     * Constructor of Owl_AuthenticationFinish
     * @param clientId Client's identity
     * @param alpha The public key alpha sent by the client in the third pass
     * @param knowledgeProofForAlpha The zero-knowledge proof for the knowledge of the private key for alpha
     * @param r The response r for proving the knowledge of t=H(usrname||password) mod n. 
     */
    public Owl_AuthenticationFinish(
        String clientId,
        ECPoint alpha,
        ECSchnorrZKP knowledgeProofForAlpha,
        BigInteger r)
    {
        Owl_Util.validateNotNull(clientId, "clientId");
        Owl_Util.validateNotNull(alpha, "alpha");
        Owl_Util.validateNotNull(r, "r");
        Owl_Util.validateNotNull(knowledgeProofForAlpha, "knowledgeProofForAlpha");

        this.clientId = clientId;
        this.knowledgeProofForAlpha = knowledgeProofForAlpha;
        this.alpha = alpha;
        this.r = r;
    }
    
    /**
     * Get the client's identity (also known as username)
     * @return The client's identity
     */
    public String getClientId()
    {
        return clientId;
    }

    /**
     * Get the public key alpha = (x2 x pi) * [X1 + X3 + X4]. sent by the client in the third pass
     * @return The public key alpha 
     */
    public ECPoint getAlpha()
    {
        return alpha;
    }

    /**
     * Get the response r as part of the zero-knowledge proof for proving the knowledge of t, r = x1 - t.h mod n where x1 is the ephemeral private key for the public key X1 sent in the first pass of Owl
     * @return The response r sent by the client in the third pass
     */
    public BigInteger getR()
    {
        return r;
    }
    
    /**
     * Get the Schnorr zero-knowledge proof for the knowledge of the private key (x2 x pi) for the public key alpha 
     * @return {@link ECSchnorrZKP}
     */
    public ECSchnorrZKP getKnowledgeProofForAlpha()
    {
        return knowledgeProofForAlpha;
    }
}