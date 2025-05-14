package org.bouncycastle.pqc.crypto.mirath;

public class MirathParameters
{
    public static final MirathParameters mirath_1a_fast = new MirathParameters(
        "Mirath-1a-fast",                         // name
        16,                               // securityLevelBytes
        73,                               // publicKeyBytes
        3728,                             // signatureBytes
        16,                               // q
        16,                               // m
        143,                              // k
        16,                               // n
        4,                                // r
        17,                               // tau
        16,                               // rho
        2,                                // mu
        4352,                             // treeLeaves
        17,                               // challenge2Bytes
        2,                                // hash2MaskBytes
        0x01,                             // hash2Mask
        118,                               // tOpen
        true,
        true
    );

    public static final MirathParameters mirath_1a_short = new MirathParameters(
        "Mirath-1a-short",                 // name
        16,                              // securityLevelBytes
        73,                              // publicKeyBytes
        3078,                            // signatureBytes
        16,                              // q
        16,                              // m
        143,                             // k
        16,                              // n
        4,                               // r
        11,                              // tau
        11,                              // rho
        3,                               // mu
        45056,                           // treeLeaves
        17,                              // challenge2Bytes
        1,                               // hash2MaskBytes
        0x7F,                            // hash2Mask
        116,                              // tOpen
        true,
        false
    );

    public static final MirathParameters mirath_1b_fast = new MirathParameters(
        "Mirath-1b-fast",                // name
        16,                             // securityLevelBytes
        57,                             // publicKeyBytes
        3456,                           // signatureBytes
        2,                              // q
        42,                             // m
        1443,                           // k
        42,                             // n
        4,                              // r
        17,                             // tau
        16,                             // rho
        8,                              // mu
        4352,                           // treeLeaves
        17,                             // challenge2Bytes
        2,                              // hash2MaskBytes
        0x01,                           // hash2Mask
        118,                             // tOpen
        false,
        true
    );

    public static final MirathParameters mirath_1b_short = new MirathParameters(
        "Mirath-1b-short",              // name
        16,                            // securityLevelBytes
        57,                            // publicKeyBytes
        2902,                          // signatureBytes
        2,                             // q
        42,                            // m
        1443,                          // k
        42,                            // n
        4,                             // r
        11,                            // tau
        11,                            // rho
        12,                            // mu
        45056,                         // treeLeaves
        17,                            // challenge2Bytes
        1,                             // hash2MaskBytes
        0x7F,                          // hash2Mask
        116,                            // tOpen
        false,
        false
    );

    public static final MirathParameters mirath_3a_fast = new MirathParameters(
        "Mirath-3a-fast",              // name
        24,                           // securityLevelBytes
        107,                          // publicKeyBytes
        8537,                         // signatureBytes
        16,                           // q
        19,                           // m
        195,                          // k
        19,                           // n
        5,                            // r
        26,                           // tau
        24,                           // rho
        2,                            // mu
        6656,                         // treeLeaves
        26,                           // challenge2Bytes
        2,                            // hash2MaskBytes
        0x03,                         // hash2Mask
        184,                           // tOpen
        true,
        true
    );

    public static final MirathParameters mirath_3a_short = new MirathParameters(
        "Mirath-3a-short",             // name
        24,                           // securityLevelBytes
        107,                          // publicKeyBytes
        6907,                         // signatureBytes
        16,                           // q
        19,                           // m
        195,                          // k
        19,                           // n
        5,                            // r
        17,                           // tau
        16,                           // rho
        3,                            // mu
        69632,                        // treeLeaves
        26,                           // challenge2Bytes
        1,                            // hash2MaskBytes
        0x1f,                         // hash2Mask
        174,                           // tOpen
        true,
        false
    );

    public static final MirathParameters mirath_3b_fast = new MirathParameters(
        "Mirath-3b-fast",              // name
        24,                           // securityLevelBytes
        84,                           // publicKeyBytes
        7936,                         // signatureBytes
        2,                            // q
        50,                           // m
        2024,                         // k
        50,                           // n
        5,                            // r
        26,                           // tau
        24,                           // rho
        8,                            // mu
        6656,                         // treeLeaves
        26,                           // challenge2Bytes
        2,                            // hash2MaskBytes
        0x03,                         // hash2Mask
        184,                           // tOpen
        false,
        true
    );

    public static final MirathParameters mirath_3b_short = new MirathParameters(
        "Mirath-3b-short",             // name
        24,                           // securityLevelBytes
        84,                           // publicKeyBytes
        6514,                         // signatureBytes
        2,                            // q
        50,                           // m
        2024,                         // k
        50,                           // n
        5,                            // r
        17,                           // tau
        16,                           // rho
        12,                           // mu
        69632,                        // treeLeaves
        26,                           // challenge2Bytes
        1,                            // hash2MaskBytes
        0x1f,                         // hash2Mask
        174,                           // tOpen
        false,
        false
    );

    public static final MirathParameters mirath_5a_fast = new MirathParameters(
        "Mirath-5a-fast",              // name
        32,                           // securityLevelBytes
        147,                          // publicKeyBytes
        15504,                        // signatureBytes
        16,                           // q
        22,                           // m
        255,                          // k
        22,                           // n
        6,                            // r
        36,                           // tau
        32,                           // rho
        2,                            // mu
        9216,                         // treeLeaves
        36,                           // challenge2Bytes
        1,                            // hash2MaskBytes
        0x0f,                         // hash2Mask
        244,                           // tOpen
        true,
        true
    );

    public static final MirathParameters mirath_5a_short = new MirathParameters(
        "Mirath-5a-short",             // name
        32,                           // securityLevelBytes
        147,                          // publicKeyBytes
        12413,                        // signatureBytes
        16,                           // q
        22,                           // m
        255,                          // k
        22,                           // n
        6,                            // r
        23,                           // tau
        22,                           // rho
        3,                            // mu
        94208,                        // treeLeaves
        35,                           // challenge2Bytes
        1,                            // hash2MaskBytes
        0x07,                         // hash2Mask
        232,                           // tOpen
        true,
        false
    );

    public static final MirathParameters mirath_5b_fast = new MirathParameters(
        "Mirath-5b-fast",              // name
        32,                           // securityLevelBytes
        112,                          // publicKeyBytes
        14262,                        // signatureBytes
        2,                            // q
        56,                           // m
        2499,                         // k
        56,                           // n
        6,                            // r
        36,                           // tau
        32,                           // rho
        8,                            // mu
        9216,                         // treeLeaves
        36,                           // challenge2Bytes
        1,                            // hash2MaskBytes
        0x0f,                         // hash2Mask
        244,                           // tOpen
        false,
        true
    );

    public static final MirathParameters mirath_5b_short = new MirathParameters(
        "Mirath-5b-short",              // name
        32,                           // securityLevelBytes
        112,                          // publicKeyBytes
        11620,                        // signatureBytes
        2,                            // q
        56,                           // m
        2499,                         // k
        56,                           // n
        6,                            // r
        23,                           // tau
        22,                           // rho
        12,                           // mu
        94208,                        // treeLeaves
        35,                           // challenge2Bytes
        1,                            // hash2MaskBytes
        0x07,                         // hash2Mask
        232,                           // tOpen
        false,
        false
    );

    private final String name;
    private final int securityLevel;
    private final int securityLevelBytes;
    private final int saltBytes;
    private final int secretKeyBytes;
    private final int publicKeyBytes;
    private final int signatureBytes;
    private final int q;
    private final int m;
    private final int k;
    private final int n;
    private final int r;
    private final int n1n2;
    private final int n1n2Bits;
    private final int n1n2Bytes;
    private final int n1n2Mask;
    private final int tau;
    private final int rho;
    private final int mu;
    private final int treeLeaves;
    private final int challenge2Bytes;
    private final int hash2MaskBytes;
    private final int hash2Mask;
    private final int tOpen;
    private final boolean isA;
    private final boolean isFast;

    private MirathParameters(String name, int securityLevelBytes, int publicKeyBytes, int signatureBytes,
                             int q, int m, int k, int n, int r, int tau,
                             int rho, int mu, int treeLeaves,
                             int challenge2Bytes, int hash2MaskBytes, int hash2Mask, int tOpen,
                             boolean isA, boolean isFast)
    {
        this.name = name;
        this.securityLevel = securityLevelBytes << 3;
        this.securityLevelBytes = securityLevelBytes;
        this.saltBytes = securityLevelBytes << 1;
        this.secretKeyBytes = securityLevelBytes << 1;
        this.publicKeyBytes = publicKeyBytes;
        this.signatureBytes = signatureBytes;
        this.q = q;
        this.m = m;
        this.k = k;
        this.n = n;
        this.r = r;
        this.n1n2 = isFast ? 256 : 4096;
        this.n1n2Bits = isFast ? 8 : 12;
        this.n1n2Bytes = isFast ? 1 : 2;
        this.n1n2Mask = isFast ? 0xff : 0x0f;
        this.tau = tau;
        this.rho = rho;
        this.mu = mu;
        this.treeLeaves = treeLeaves;
        this.challenge2Bytes = challenge2Bytes;
        this.hash2MaskBytes = hash2MaskBytes;
        this.hash2Mask = hash2Mask;
        this.tOpen = tOpen;
        this.isA = isA;
        this.isFast = isFast;
    }

    // Getters for all fields
    public String getName()
    {
        return name;
    }

    public int getSecurityLevel()
    {
        return securityLevel;
    }

    public int getSecurityLevelBytes()
    {
        return securityLevelBytes;
    }

    public int getSaltBytes()
    {
        return saltBytes;
    }

    public int getSecretKeyBytes()
    {
        return secretKeyBytes;
    }

    public int getPublicKeyBytes()
    {
        return publicKeyBytes;
    }

    public int getSignatureBytes()
    {
        return signatureBytes;
    }

    public int getQ()
    {
        return q;
    }

    public int getM()
    {
        return m;
    }

    public int getK()
    {
        return k;
    }

    public int getN()
    {
        return n;
    }

    public int getR()
    {
        return r;
    }

    public int getN1()
    {
        return n1n2;
    }

    public int getN2()
    {
        return n1n2;
    }

    public int getN1Bits()
    {
        return n1n2Bits;
    }

    public int getN1Bytes()
    {
        return n1n2Bytes;
    }

    public int getN1Mask()
    {
        return n1n2Mask;
    }

    public int getTau()
    {
        return tau;
    }

    public int getRho()
    {
        return rho;
    }

    public int getMu()
    {
        return mu;
    }

    public int getTreeLeaves()
    {
        return treeLeaves;
    }

    public int getChallenge2Bytes()
    {
        return challenge2Bytes;
    }

    public int getHash2MaskBytes()
    {
        return hash2MaskBytes;
    }

    public int getHash2Mask()
    {
        return hash2Mask;
    }

    public int getTOpen()
    {
        return tOpen;
    }

    boolean isA()
    {
        return isA;
    }

    boolean isFast()
    {
        return isFast;
    }
}
