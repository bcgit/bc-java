package org.example;

import org.bouncycastle.math.ec.ECPoint;

/**
 * The payload sent by the server during the second pass of an Owl exchange.
 * <p>
 * Each {@link Owl_Server} creates and sends an instance
 * of this payload to the {@link Owl_Client}.
 * The payload to send should be created via
 * {@link Owl_Server#authenticationServerResponse(Owl_AuthenticationInitiate, Owl_FinishRegistration)}.
 * <p>
 * Each {@link Owl_Server} must also validate the payload
 * received from the {@link Owl_Client} which comes in the form of {@link Owl_AuthenticationInitiate}.
 * The {@link Owl_Server} must retrieve the {@link Owl_FinishRegistration} 
 * from wherever the server securely stored the initial login information.
 * The received payload should be validated via the same function (in the same call).
 */
public class Owl_AuthenticationServerResponse
{
    /**
     * Unique identifier for the server.
     * <p>
     * Must not be the same as the unique identifier for the client (client username).
     * </p>
     */
    private final String serverId;

    /**
     * The value of g^x3
     */
    private final ECPoint gx3;

    /**
     * The value of g^x4
     */
    private final ECPoint gx4;

    /**
     * The zero knowledge proof for x3.
     * <p>
     * This is a class {@link ECSchnorrZKP} with two fields, containing {g^v, r} for x3.
     * </p>
     */
    private final ECSchnorrZKP knowledgeProofForX3;

    /**
     * The zero knowledge proof for x4.
     * <p>
     * This is a class {@link ECSchnorrZKP} with two fields, containing {g^v, r} for x4.
     * </p>
     */
    private final ECSchnorrZKP knowledgeProofForX4;

    /**
     * The value for beta = (X1 + X2 + X3)^x4pi
     */
    private final ECPoint beta;

    /**
     * The zero knowledge proof for beta.
     * <p>
     * This is a class {@link ECSchnorrZKP} with two fields, containing {g^v, r} for x4pi.
     * </p>
     */
    private final ECSchnorrZKP knowledgeProofForBeta;

    /**
     * Constructor for Owl_AuthenticationServerResponse
     * @param serverId The server's identity
     * @param gx3 The public key X3 = x3 * [G]
     * @param gx4 The public key X4 = x4 * [G]
     * @param knowledgeProofForX3 The zero-knowledge proof for the knowledge of x3
     * @param knowledgeProofForX4 The zero-knowledge proof for the knowledge of x4 
     * @param beta The public key beta = (x4 x pi) * [X1 + X2 + X3]
     * @param knowledgeProofForBeta The zero-knowledge proof for the knowledge of (x4 x pi) for beta
     */
    public Owl_AuthenticationServerResponse(
        String serverId,
        ECPoint gx3,
        ECPoint gx4,
        ECSchnorrZKP knowledgeProofForX3,
        ECSchnorrZKP knowledgeProofForX4,
        ECPoint beta,
        ECSchnorrZKP knowledgeProofForBeta)
    {
        Owl_Util.validateNotNull(serverId, "serverId");
        Owl_Util.validateNotNull(gx3, "gx3");
        Owl_Util.validateNotNull(gx4, "gx4");
        Owl_Util.validateNotNull(knowledgeProofForX3, "knowledgeProofForX3");
        Owl_Util.validateNotNull(knowledgeProofForX4, "knowledgeProofForX4");
        Owl_Util.validateNotNull(beta, "beta");
        Owl_Util.validateNotNull(knowledgeProofForBeta, "knowledgeProofForBeta");

        this.serverId = serverId;
        this.gx3 = gx3;
        this.gx4 = gx4;
        this.knowledgeProofForX3 = knowledgeProofForX3;
        this.knowledgeProofForX4 = knowledgeProofForX4;
        this.beta = beta;
        this.knowledgeProofForBeta = knowledgeProofForBeta;
    }

    /**
     * Get the server's identity
     * @return The server's identity
     */
    public String getServerId()
    {
        return serverId;
    }

    /**
     * Get the public key X3 = x3 * [G]
     * @return The public key X3
     */
    public ECPoint getGx3()
    {
        return gx3;
    }

    /**
     * Get the public key X4 = x4 * [G]
     * @return The public key X4
     */
    public ECPoint getGx4()
    {
        return gx4;
    }

    /**
     * Get the zero-knowledge proof for the knowledge of x3 for X3 = x3 * [G]
     * @return {@link ECSchnorrZKP}
     */
    public ECSchnorrZKP getKnowledgeProofForX3()
    {
        return knowledgeProofForX3;
    }

    /**
     * Get the zero-knowledge proof for the knowledge of x4 for X4 = x4 * [G]
     * @return {@link ECSchnorrZKP}
     */
    public ECSchnorrZKP getKnowledgeProofForX4()
    {
        return knowledgeProofForX4;
    }

    /**
     * Get the public key beta = (x4 x pi) * [X1 + X2 + X3]
     * @return The public key beta
     */
    public ECPoint getBeta()
    {
        return beta;
    }

    /**
     * Get the zero-knowledge proof for the knowledge of (x4 x pi) for the public key beta = (x4 x pi) * [X1 + X2 + X3]
     * @return {@link ECSchnorrZKP}
     */
    public ECSchnorrZKP getKnowledgeProofForBeta()
    {
        return knowledgeProofForBeta;
    }

}