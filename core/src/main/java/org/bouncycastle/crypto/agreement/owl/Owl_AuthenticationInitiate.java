package org.example;

import org.bouncycastle.math.ec.ECPoint;

/**
 * The payload sent by the client in the first pass of an Owl exchange.
 * <p>
 * Each {@link Owl_Client} creates and sends an instance
 * of this payload to the {@link Owl_Server}.
 * The payload to send should be created via
 * {@link Owl_Client#authenticationInitiate()}.
 */
public class Owl_AuthenticationInitiate
{

    /**
     * Unique identifier for the client (this is the username)
     * <p>
     * ClientId must not be the same as the server unique identifier,
     * </p>
     */
    private final String clientId;

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
    
    /**
     * Constructor of Owl_AuthenticationInitiate
     * @param clientId the client's identity (or username)
     * @param gx1 The public key X1 = x1 * [G]
     * @param gx2 The public key X2 = x2 * [G]
     * @param knowledgeProofForX1 The zero-knowledge proof for proving the knowledge of x1
     * @param knowledgeProofForX2 The zero-knowledge proof for proving the knowledge of x2
     */
    public Owl_AuthenticationInitiate(
        String clientId,
        ECPoint gx1,
        ECPoint gx2,
        ECSchnorrZKP knowledgeProofForX1,
        ECSchnorrZKP knowledgeProofForX2)
    {
        Owl_Util.validateNotNull(clientId, "clientId");
        Owl_Util.validateNotNull(gx1, "gx1");
        Owl_Util.validateNotNull(gx2, "gx2");
        Owl_Util.validateNotNull(knowledgeProofForX1, "knowledgeProofForX1");
        Owl_Util.validateNotNull(knowledgeProofForX2, "knowledgeProofForX2");

        this.clientId = clientId;
        this.gx1 = gx1;
        this.gx2 = gx2;
        this.knowledgeProofForX1 = knowledgeProofForX1;
        this.knowledgeProofForX2 = knowledgeProofForX2;
    }

    /**
     * Get the client's identity (or username)
     * @return The client's identity
     */
    public String getClientId()
    {
        return clientId;
    }

    /**
     * Get the client's public key X1 = x1 * [G] in the first pass of Owl
     * @return The client's public key X1 
     */
    public ECPoint getGx1()
    {
        return gx1;
    }

    /**
     * Get the client's public key X2 = x2 * [G] in the first pass of Owl
     * @return The client's public key X2 
     */
    public ECPoint getGx2()
    {
        return gx2;
    }

    /**
     * Get the zero-knowledge proof for the knowledge of x1
     * @return {@link ECSchnorrZKP}
     */
    public ECSchnorrZKP getKnowledgeProofForX1()
    {
        return knowledgeProofForX1;
    }

    /**
     * Get the zero-knowledge proof for the knowledge of x2
     * @return {@link ECSchnorrZKP}
     */
    public ECSchnorrZKP getKnowledgeProofForX2()
    {
        return knowledgeProofForX2;
    }

}