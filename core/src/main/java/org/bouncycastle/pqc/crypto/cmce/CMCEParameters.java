package org.bouncycastle.pqc.crypto.cmce;

import org.bouncycastle.crypto.CipherParameters;

import java.security.SecureRandom;

public class CMCEParameters
    implements CipherParameters
{
    private int m;

    private int n;

    private int t;

    private int[] poly;

    private boolean isCompressed;

    private CMCEEngine engine;

    private SecureRandom random;



    public CMCEParameters(int m, int n, int t, int[] p, boolean isCompressed, SecureRandom random)
    {
        this.isCompressed = isCompressed;
        this.m = m;
        this.n = n;
        this.t = t;
        this.poly = p;
        this.engine = new CMCEEngine(m, n, t, p, isCompressed);
        this.random = random;
    }

    public int getM()
    {
        return m;
    }

    public int getN()
    {
        return n;
    }

    public int getT()
    {
        return t;
    }

    public int[] getPoly()
    {
        return poly;
    }

    public CMCEEngine getEngine()
    {
        return engine;
    }

    public SecureRandom getRandom()
    {
        return random;
    }
}
