package org.bouncycastle.pqc.crypto.ntru;

import java.security.SecureRandom;

import org.bouncycastle.crypto.KeyGenerationParameters;

/**
 * Key generation parameters for NTRU.
 */
public class NTRUKeyGenerationParameters
    extends KeyGenerationParameters
{
    private final NTRUParameters ntruParameters;

    /**
     * Constructor.
     *
     * @param random a secure random number generator
     * @param params an NTRU parameter set
     */
    public NTRUKeyGenerationParameters(SecureRandom random, NTRUParameters params)
    {
        // We won't be using strength as the key length differs between public & private key
        super(random, 0);
        this.ntruParameters = params;
    }

    /**
     * @return the NTRU parameter set used for this key generation
     */
    public NTRUParameters getParameters()
    {
        return ntruParameters;
    }
}
