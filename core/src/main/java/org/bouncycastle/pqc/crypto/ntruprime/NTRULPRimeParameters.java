package org.bouncycastle.pqc.crypto.ntruprime;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.pqc.crypto.KEMParameters;

/**
 * NTRU LPRime Parameter Specs
 */
public class NTRULPRimeParameters
    implements KEMParameters
{
    public static final NTRULPRimeParameters ntrulpr653 = new NTRULPRimeParameters("ntrulpr653", 653, 4621, 252, 289,
        2175, 113, 2031, 290,
        865, 897, 1125, 16);
    public static final NTRULPRimeParameters ntrulpr761 = new NTRULPRimeParameters("ntrulpr761", 761, 4591, 250, 292,
        2156, 114, 2007, 287,
        1007, 1039, 1294, 16);
    public static final NTRULPRimeParameters ntrulpr857 = new NTRULPRimeParameters("ntrulpr857", 857, 5167, 281, 329,
        2433, 101, 2265, 324,
        1152, 1184, 1463, 16);
    public static final NTRULPRimeParameters ntrulpr953 = new NTRULPRimeParameters("ntrulpr953", 953, 6343, 345, 404,
        2997, 82, 2798, 400,
        1317, 1349, 1652, 24);
    public static final NTRULPRimeParameters ntrulpr1013 = new NTRULPRimeParameters("ntrulpr1013", 1013, 7177, 392, 450,
        3367, 73, 3143, 449,
        1423, 1455, 1773, 24);
    public static final NTRULPRimeParameters ntrulpr1277 = new NTRULPRimeParameters("ntrulpr1277", 1277, 7879, 429, 502,
        3724, 66, 3469, 496,
        1815, 1847, 2231, 32);

    private final String name;
    private final int p;
    private final int q;
    private final int w;
    private final int delta;
    private final int tau0;
    private final int tau1;
    private final int tau2;
    private final int tau3;
    private final int roundedPolynomialBytes;
    private final int publicKeyBytes;
    private final int privateKeyBytes;
    private final int sharedKeyBytes;

    /**
     * Construct Parameter set and initialize engine
     *
     * @param name                   name of parameter spec
     * @param p                      p is prime and degree of ring polynomial
     * @param q                      q is prime and used for irreducible ring polynomial
     * @param w                      w is a positive integer less than p
     * @param delta                  delta
     * @param tau0                   tau0
     * @param tau1                   tau1
     * @param tau2                   tau2
     * @param tau3                   tau3
     * @param roundedPolynomialBytes roundedPolynomialBytes is bytes taken to represent rounded polynomial
     * @param publicKeyBytes         Public Key byte length
     * @param privateKeyBytes        Private Key byte length
     */
    private NTRULPRimeParameters(String name, int p, int q, int w, int delta, int tau0, int tau1, int tau2, int tau3, int roundedPolynomialBytes, int publicKeyBytes, int privateKeyBytes, int sharedKeyBytes)
    {
        this.name = name;
        this.p = p;
        this.q = q;
        this.w = w;
        this.delta = delta;
        this.tau0 = tau0;
        this.tau1 = tau1;
        this.tau2 = tau2;
        this.tau3 = tau3;
        this.roundedPolynomialBytes = roundedPolynomialBytes;
        this.publicKeyBytes = publicKeyBytes;
        this.privateKeyBytes = privateKeyBytes;
        this.sharedKeyBytes = sharedKeyBytes;
    }

    public String getName()
    {
        return name;
    }

    public int getP()
    {
        return p;
    }

    public int getQ()
    {
        return q;
    }

    public int getW()
    {
        return w;
    }

    public int getDelta()
    {
        return delta;
    }

    public int getTau0()
    {
        return tau0;
    }

    public int getTau1()
    {
        return tau1;
    }

    public int getTau2()
    {
        return tau2;
    }

    public int getTau3()
    {
        return tau3;
    }

    public int getPublicKeyBytes()
    {
        return publicKeyBytes;
    }

    public int getPrivateKeyBytes()
    {
        return privateKeyBytes;
    }

    public int getRoundedPolynomialBytes()
    {
        return roundedPolynomialBytes;
    }

    public int getSessionKeySize()
    {
        return sharedKeyBytes * 8;
    }

}
