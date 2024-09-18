package org.bouncycastle.crypto.agreement.ecjpake;

import java.math.BigInteger;
import org.bouncycastle.math.ec.ECPoint;

/**
 * Package protected class for the zero knowledge proof, for an EC J-PAKE exchange.
 * <p>
 * V = G x [v]
 * r = v - d * c mod n
 * <p>
 */
class ECSchnorrZKP {
    
    private final ECPoint V;
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
