package org.bouncycastle.pqc.crypto.falcon;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.params.PQCParameters;

public class FalconParameters
    implements CipherParameters, PQCParameters
{
    public static final FalconParameters falcon_512 = new FalconParameters("falcon-512", 9, 40);
    public static final FalconParameters falcon_1024 = new FalconParameters("falcon-1024", 10, 40);

    private final String name;
    private final int logn;
    private final int nonce_length;

    private FalconParameters(String name, int logn, int nonce_length)
    {
        if (logn < 1 || logn > 10)
        {
            throw new IllegalArgumentException("Log N degree should be between 1 and 10");
        }
        this.name = name;
        this.logn = logn;
        this.nonce_length = nonce_length;
    }

    public int getLogN()
    {
        return logn;
    }

    int getNonceLength()
    {
        return nonce_length;
    }

    public String getName()
    {
        return name;
    }

    /**
     * Return the NIST security category claimed for this parameter set in the round 3
     * submission: 1 for Falcon-512 and 5 for Falcon-1024. FN-DSA (FIPS 206) is still in
     * development and may carry its own categorisation.
     */
    public int getSecurityCategory()
    {
        return (logn <= 9) ? 1 : 5;
    }

    /**
     * Return the classical security strength claimed for this parameter set: 128 bits for
     * Falcon-512 and 256 bits for Falcon-1024.
     */
    public int getClassicalSecurityStrength()
    {
        return (logn <= 9) ? 128 : 256;
    }
}
