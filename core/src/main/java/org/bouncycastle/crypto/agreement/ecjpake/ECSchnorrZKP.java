package org.bouncycastle.crypto.agreement.ecjpake;

import java.math.BigInteger;
import org.bouncycastle.math.ec.ECPoint;

/**
 * Package protected class containing zero knowledge proof, for an EC J-PAKE exchange.
 *</p>
 *
 *
 */ 
class ECSchnorrZKP {

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
    
    ECPoint getV() {
        return V;
    }
    
    BigInteger getr() {
        return r;
    }
}
