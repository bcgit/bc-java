package org.bouncycastle.pqc.crypto.ntruprime;

import org.bouncycastle.pqc.crypto.KEMParameters;

/**
 * StreamLined NTRU Prime Parameter Specs
 */
public class SNTRUPrimeParameters
    implements KEMParameters
{
    public static final SNTRUPrimeParameters sntrup653 = new SNTRUPrimeParameters("sntrup653", 653, 4621, 288,
                                                                    994, 865, 994, 1518, 16);
    public static final SNTRUPrimeParameters sntrup761 = new SNTRUPrimeParameters("sntrup761", 761, 4591, 286,
                                                                    1158, 1007, 1158, 1763, 16);
    public static final SNTRUPrimeParameters sntrup857 = new SNTRUPrimeParameters("sntrup857", 857, 5167, 322,
                                                                    1322, 1152, 1322, 1999, 16);
    public static final SNTRUPrimeParameters sntrup953 = new SNTRUPrimeParameters("sntrup953", 953, 6343, 396,
                                                                    1505, 1317, 1505, 2254, 24);
    public static final SNTRUPrimeParameters sntrup1013 = new SNTRUPrimeParameters("sntrup1013", 1013, 7177, 448,
                                                                    1623, 1423, 1623, 2417, 24);
    public static final SNTRUPrimeParameters sntrup1277 = new SNTRUPrimeParameters("sntrup1277", 1277, 7879, 492,
                                                                    2067, 1815, 2067, 3059, 32);

    private final String name;
    private final int p;
    private final int q;
    private final int w;
    private final int rqPolynomialBytes;
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
     * @param rqPolynomialBytes      rqPolynomialBytes is bytes taken to represent the ring polynomial
     * @param roundedPolynomialBytes roundedPolynomialBytes is bytes taken to represent rounded polynomial
     * @param publicKeyBytes         Public Key byte length
     * @param privateKeyBytes        Private Key byte length
     */
    private SNTRUPrimeParameters(String name, int p, int q, int w, int rqPolynomialBytes, int roundedPolynomialBytes, int publicKeyBytes, int privateKeyBytes, int sharedKeyBytes)
    {
        this.name = name;
        this.p = p;
        this.q = q;
        this.w = w;
        this.rqPolynomialBytes = rqPolynomialBytes;
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

    public int getPublicKeyBytes()
    {
        return publicKeyBytes;
    }

    public int getPrivateKeyBytes()
    {
        return privateKeyBytes;
    }

    public int getRqPolynomialBytes()
    {
        return rqPolynomialBytes;
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
