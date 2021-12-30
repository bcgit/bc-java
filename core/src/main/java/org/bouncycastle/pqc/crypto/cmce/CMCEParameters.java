package org.bouncycastle.pqc.crypto.cmce;

import org.bouncycastle.crypto.CipherParameters;

public class CMCEParameters
    implements CipherParameters
{
    private int m;

    private int n;

    private int t;

    private int[] poly;

    // TODO: unused?
    private boolean isCompressed;

    private CMCEEngine engine;
    
    public CMCEParameters(int m, int n, int t, int[] p, boolean isCompressed)
    {
        this.isCompressed = isCompressed;
        this.m = m;
        this.n = n;
        this.t = t;
        this.poly = p;
        this.engine = new CMCEEngine(m, n, t, p, isCompressed);
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
}
