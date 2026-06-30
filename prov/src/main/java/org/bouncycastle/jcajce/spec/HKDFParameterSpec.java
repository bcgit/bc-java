package org.bouncycastle.jcajce.spec;

import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.KeySpec;

import org.bouncycastle.util.Arrays;

public class HKDFParameterSpec
    implements KeySpec, AlgorithmParameterSpec
{
    private final byte[] ikm;
    private final byte[] salt;
    private final byte[] info;
    private final int outputLength;

    public HKDFParameterSpec(byte[] ikm, byte[] salt, byte[] info, int outputLength)
    {
        if (ikm == null)
        {
            throw new IllegalArgumentException("IKM (input keying material) should not be null");
        }

        this.ikm = Arrays.clone(ikm);
        this.salt = (salt == null || salt.length == 0) ? null : Arrays.clone(salt);
        this.info = (info == null) ? new byte[0] : Arrays.clone(info);
        this.outputLength = outputLength;
    }

    /**
     * Returns the input keying material or seed.
     *
     * @return the keying material
     */
    public byte[] getIKM()
    {
        return Arrays.clone(ikm);
    }

    /**
     * Returns if step 1: extract has to be skipped or not.
     *
     * @return true for skipping, false for no skipping of step 1
     */
    public boolean skipExtract()
    {
        return false;
    }

    /**
     * Returns the salt, or null if the salt should be generated as a byte array
     * of HashLen zeros.
     *
     * @return the salt, or null
     */
    public byte[] getSalt()
    {
        return Arrays.clone(salt);
    }

    /**
     * Returns the info field, which may be empty (null is converted to empty).
     *
     * @return the info field, never null
     */
    public byte[] getInfo()
    {
        return Arrays.clone(info);
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
