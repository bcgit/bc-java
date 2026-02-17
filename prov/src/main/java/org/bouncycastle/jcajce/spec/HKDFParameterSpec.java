package org.bouncycastle.jcajce.spec;

import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.KeySpec;

import org.bouncycastle.crypto.params.HKDFParameters;

public class HKDFParameterSpec
    implements KeySpec, AlgorithmParameterSpec
{
    private final HKDFParameters hkdfParameters;
    private final int outputLength;

    public HKDFParameterSpec(byte[] ikm, byte[] salt, byte[] info, int outputLength)
    {
        this.hkdfParameters = new HKDFParameters(ikm, salt, info);
        this.outputLength = outputLength;
    }

    /**
     * Returns the input keying material or seed.
     *
     * @return the keying material
     */
    public byte[] getIKM()
    {
        return hkdfParameters.getIKM();
    }

    /**
     * Returns if step 1: extract has to be skipped or not
     *
     * @return true for skipping, false for no skipping of step 1
     */
    public boolean skipExtract()
    {
        return hkdfParameters.skipExtract();
    }

    /**
     * Returns the salt, or null if the salt should be generated as a byte array
     * of HashLen zeros.
     *
     * @return the salt, or null
     */
    public byte[] getSalt()
    {
        return hkdfParameters.getSalt();
    }

    /**
     * Returns the info field, which may be empty (null is converted to empty).
     *
     * @return the info field, never null
     */
    public byte[] getInfo()
    {
        return hkdfParameters.getInfo();
    }

    /**
     * Returns the length (in bytes) of the output resulting from these parameters.
     *
     * @return output length, in bytes.
     */
    public int getOutputLength()
    {
        return outputLength;
    }
}
