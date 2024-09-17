package org.bouncycastle.crypto.agreement.ecjpake;

import java.math.BigInteger;
import org.bouncycastle.math.ec.ECPoint;


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