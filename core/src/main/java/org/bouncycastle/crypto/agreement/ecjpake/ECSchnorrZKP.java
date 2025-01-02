package org.bouncycastle.crypto.agreement.ecjpake;

import java.math.BigInteger;

import org.bouncycastle.math.ec.ECPoint;

/**
 * Package protected class containing zero knowledge proof, for an EC J-PAKE exchange.
 * <p>
 * This class encapsulates the values involved in the Schnorr
 * zero-knowledge proof used in the EC J-PAKE protocol.
 * <p>
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

    ECSchnorrZKP(ECPoint V, BigInteger r)
    {
        this.V = V;
        this.r = r;
    }

    public ECPoint getV()
    {
        return V;
    }

    public BigInteger getr()
    {
        return r;
    }
}
