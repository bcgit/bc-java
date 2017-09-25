package org.bouncycastle.crypto.params;

import org.bouncycastle.crypto.CipherParameters;

/**
 * Parameters for GOST 3412 2015 cipher algorithm.
 */
public class GOST3412ParametersWithIV implements CipherParameters {

    private byte[]              iv;
    private CipherParameters    parameters;
    private int s;
    private int m;

    public GOST3412ParametersWithIV(byte[] iv, CipherParameters parameters, int s, int m) {
        this.iv = iv;
        this.parameters = parameters;
        this.s = s;
        this.m = m;
    }

    public GOST3412ParametersWithIV(byte[] iv, CipherParameters parameters, int m) {
        this.iv = iv;
        this.parameters = parameters;
        this.m = m;
    }

    public byte[] getIV() {
        return iv;
    }

    public CipherParameters getParameters() {
        return parameters;
    }

    public int getS() {
        return s;
    }

    public int getM() {
        return m;
    }
}
