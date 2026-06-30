package org.bouncycastle.crypto.agreement.owl;

import java.math.BigInteger;

import org.bouncycastle.math.ec.ECPoint;

/**
 * Schnorr non-interactive zero-knowledge proof over an elliptic curve, as used in the Owl key
 * exchange. The {(V, r)} pair follows the RFC 8235 §3.2 EC-Schnorr-Signature encoding: prover
 * picks ephemeral v in [1, n-1], publishes commitment V = [v]G alongside response r = v - d*c
 * mod n, where d is the prover's private key and c is the challenge hash. The verifier
 * recomputes c and checks V == [r]G + [c]X.
 */
public class ECSchnorrZKP
{

    /**
     * The value of V = G x [v].
     */
    private final ECPoint V;

    /**
     * The value of r = v - d * c mod n
     */
    private final BigInteger r;

    /**
     * Constructor for ECSchnorrZKP
     * 
     * @param V Prover's commitment V = G x [v]
     * @param r Prover's response r to a challenge c, r = v - d * c mod n
     */
    public ECSchnorrZKP(ECPoint V, BigInteger r)
    {
        this.V = V;
        this.r = r;
    }

    /**
     * Get the prover's commitment V = G x [v] where G is a base point on the elliptic curve and v is an ephemeral secret
     * @return The prover's commitment
     */
    public ECPoint getV()
    {
        return V;
    }

    /**
     * Get the prover's response r to the challenge c, r = v - d * c mod n where d is the prover's private key
     * @return The prover's response 
     */
    public BigInteger getr()
    {
        return r;
    }
}
