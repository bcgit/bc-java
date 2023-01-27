package org.bouncycastle.pqc.crypto.bike;

import org.bouncycastle.pqc.crypto.KEMParameters;

public class BIKEParameters
    implements KEMParameters
{
    // 128 bits security
    public static final BIKEParameters bike128 = new BIKEParameters("bike128", 12323, 142, 134, 256, 5, 3, 128);

    // 192 bits security
    public static final BIKEParameters bike192 = new BIKEParameters("bike192", 24659, 206, 199, 256, 5, 3, 192);

    // 256 bits security
    public static final BIKEParameters bike256 = new BIKEParameters("bike256", 40973, 274, 264, 256, 5, 3, 256);

    private String name;
    private int r;
    private int w;
    private int t;
    private int l;
    private int nbIter;
    private int tau;
    private final int defaultKeySize;
    private BIKEEngine bikeEngine;

    private BIKEParameters(String name, int r, int w, int t, int l, int nbIter, int tau, int defaultKeySize)
    {
        this.name = name;
        this.r = r;
        this.w = w;
        this.t = t;
        this.l = l;
        this.nbIter = nbIter;
        this.tau = tau;
        this.defaultKeySize = defaultKeySize;
        this.bikeEngine = new BIKEEngine(r, w, t, l, nbIter, tau);
    }

    public int getR()
    {
        return r;
    }

    public int getRByte()
    {
        return (r + 7) / 8;
    }

    public int getLByte()
    {
        return l / 8;
    }

    public int getW()
    {
        return w;
    }

    public int getT()
    {
        return t;
    }

    public int getL()
    {
        return l;
    }

    public int getNbIter()
    {
        return nbIter;
    }

    public int getTau()
    {
        return tau;
    }

    public String getName()
    {
        return name;
    }

    public int getSessionKeySize()
    {
        return defaultKeySize;
    }

    BIKEEngine getEngine()
    {
        return bikeEngine;
    }
}
