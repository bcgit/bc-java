package org.bouncycastle.pqc.crypto.ntruplus;

public class NTRUPlusParameters
{
    // Parameter sets for different security levels
    public static final NTRUPlusParameters NTRUPLUS_768 = new NTRUPlusParameters(
        "NTRUPLUS_768",      // name
        768,                 // NTRUPLUS_N
        3457,                // NTRUPLUS_Q
        32,                  // NTRUPLUS_SYMBYTES
        32,                  // NTRUPLUS_SSBYTES
        1152,                // NTRUPLUS_POLYBYTES
        1152,                // NTRUPLUS_PUBLICKEYBYTES
        (1152 << 1) + 32,    // NTRUPLUS_SECRETKEYBYTES: (POLYBYTES << 1) + SYMBYTES
        1152,                // NTRUPLUS_CIPHERTEXTBYTES
        12929,               // NTRUPLUS_QINV
        -886,                // NTRUPLUS_OMEGA
        867,                 // NTRUPLUS_Rsq
        -682                 // NTRUPLUS_Rinv
    );

    public static final NTRUPlusParameters NTRUPLUS_864 = new NTRUPlusParameters(
        "NTRUPLUS_864",      // name
        864,                 // NTRUPLUS_N
        3457,                // NTRUPLUS_Q
        32,                  // NTRUPLUS_SYMBYTES
        32,                  // NTRUPLUS_SSBYTES
        1296,                // NTRUPLUS_POLYBYTES
        1296,                // NTRUPLUS_PUBLICKEYBYTES
        (1296 << 1) + 32,    // NTRUPLUS_SECRETKEYBYTES
        1296,                // NTRUPLUS_CIPHERTEXTBYTES
        12929,               // NTRUPLUS_QINV
        -886,                // NTRUPLUS_OMEGA
        867,                 // NTRUPLUS_Rsq
        -682                 // NTRUPLUS_Rinv
    );

    public static final NTRUPlusParameters NTRUPLUS_1152 = new NTRUPlusParameters(
        "NTRUPLUS_1152",     // name
        1152,                // NTRUPLUS_N
        3457,                // NTRUPLUS_Q
        32,                  // NTRUPLUS_SYMBYTES
        32,                  // NTRUPLUS_SSBYTES
        1728,                // NTRUPLUS_POLYBYTES
        1728,                // NTRUPLUS_PUBLICKEYBYTES
        (1728 << 1) + 32,    // NTRUPLUS_SECRETKEYBYTES
        1728,                // NTRUPLUS_CIPHERTEXTBYTES
        12929,               // NTRUPLUS_QINV
        -886,                // NTRUPLUS_OMEGA
        867,                 // NTRUPLUS_Rsq
        -682                 // NTRUPLUS_Rinv
    );

    // Instance fields
    private final String name;
    private final int n;                    // NTRUPLUS_N
    private final int q;                    // NTRUPLUS_Q
    private final int symBytes;             // NTRUPLUS_SYMBYTES
    private final int ssBytes;              // NTRUPLUS_SSBYTES
    private final int polyBytes;            // NTRUPLUS_POLYBYTES
    private final int publicKeyBytes;       // NTRUPLUS_PUBLICKEYBYTES
    private final int secretKeyBytes;       // NTRUPLUS_SECRETKEYBYTES
    private final int ciphertextBytes;      // NTRUPLUS_CIPHERTEXTBYTES
    private final int qInv;                 // NTRUPLUS_QINV
    private final int omega;                // NTRUPLUS_OMEGA
    private final int rSquared;             // NTRUPLUS_Rsq (R^2 mod q)
    private final int rInv;                 // NTRUPLUS_Rinv

    private NTRUPlusParameters(String name, int n, int q, int symBytes, int ssBytes,
                               int polyBytes, int publicKeyBytes, int secretKeyBytes,
                               int ciphertextBytes, int qInv, int omega,
                               int rSquared, int rInv)
    {
        this.name = name;
        this.n = n;
        this.q = q;
        this.symBytes = symBytes;
        this.ssBytes = ssBytes;
        this.polyBytes = polyBytes;
        this.publicKeyBytes = publicKeyBytes;
        this.secretKeyBytes = secretKeyBytes;
        this.ciphertextBytes = ciphertextBytes;
        this.qInv = qInv;
        this.omega = omega;
        this.rSquared = rSquared;
        this.rInv = rInv;
    }

    // Getters for all parameters
    public String getName()
    {
        return name;
    }

    public int getN()
    {
        return n;
    }

    public int getQ()
    {
        return q;
    }

    public int getSymBytes()
    {
        return symBytes;
    }

    public int getSsBytes()
    {
        return ssBytes;
    }

    public int getPolyBytes()
    {
        return polyBytes;
    }

    public int getPublicKeyBytes()
    {
        return publicKeyBytes;
    }

    public int getSecretKeyBytes()
    {
        return secretKeyBytes;
    }

    public int getCiphertextBytes()
    {
        return ciphertextBytes;
    }

    public int getQInv()
    {
        return qInv;
    }

    public int getOmega()
    {
        return omega;
    }

    public int getRSquared()
    {
        return rSquared;
    }

    public int getRInv()
    {
        return rInv;
    }

    /**
     * Derived parameter: Number of coefficients per polynomial
     */
    public int getCoeffsPerPoly()
    {
        return n;
    }

    /**
     * Derived parameter: Number of bytes needed for a packed polynomial
     */
    public int getPackedPolyBytes()
    {
        // Each coefficient needs 12 bits (since q=3457 < 2^12)
        // Packed as 2 coefficients in 3 bytes
        return (n * 3 + 1) / 2;  // This equals polyBytes
    }
}