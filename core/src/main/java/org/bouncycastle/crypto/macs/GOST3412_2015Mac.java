package org.bouncycastle.crypto.macs;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.Mac;


public class GOST3412_2015Mac implements Mac {

    public void init(CipherParameters params) throws IllegalArgumentException {

    }

    public String getAlgorithmName() {
        return null;
    }

    public int getMacSize() {
        return 0;
    }

    public void update(byte in) throws IllegalStateException {

    }

    public void update(byte[] in, int inOff, int len) throws DataLengthException, IllegalStateException {

    }

    public int doFinal(byte[] out, int outOff) throws DataLengthException, IllegalStateException {
        return 0;
    }

    public void reset() {

    }
}
