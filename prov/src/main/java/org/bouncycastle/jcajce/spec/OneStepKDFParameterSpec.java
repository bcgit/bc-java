package org.bouncycastle.jcajce.spec;

import java.security.spec.AlgorithmParameterSpec;

import org.bouncycastle.util.Arrays;

/**
 * Derivation parameters for the NIST SP 800-56C Rev. 2 Section 4.1 one-step key derivation function
 * ({@code KDF.getInstance("ONESTEP-SHA256")}, "ONESTEP-HMACSHA256", "ONESTEP-KMAC128", ...): the shared
 * secret Z, the FixedInfo, the output length, and for the HMAC and KMAC options an optional salt.
 */
public class OneStepKDFParameterSpec
    implements AlgorithmParameterSpec
{
    private final byte[] z;
    private final byte[] salt;
    private final byte[] fixedInfo;
    private final int outputLength;

    /**
     * Hash option, or HMAC/KMAC with the standard's default salt.
     *
     * @param z            the shared secret.
     * @param fixedInfo    the FixedInfo, may be null.
     * @param outputLength the number of bytes to derive.
     */
    public OneStepKDFParameterSpec(byte[] z, byte[] fixedInfo, int outputLength)
    {
        this(z, null, fixedInfo, outputLength);
    }

    /**
     * @param z            the shared secret.
     * @param salt         the salt keying HMAC or KMAC, or null for the standard's default salt; ignored by
     *                     the hash option.
     * @param fixedInfo    the FixedInfo, may be null.
     * @param outputLength the number of bytes to derive.
     */
    public OneStepKDFParameterSpec(byte[] z, byte[] salt, byte[] fixedInfo, int outputLength)
    {
        if (z == null)
        {
            throw new IllegalArgumentException("shared secret Z should not be null");
        }
        if (outputLength <= 0)
        {
            throw new IllegalArgumentException("outputLength must be positive");
        }
        this.z = Arrays.clone(z);
        this.salt = (salt == null || salt.length == 0) ? null : Arrays.clone(salt);
        this.fixedInfo = (fixedInfo == null) ? new byte[0] : Arrays.clone(fixedInfo);
        this.outputLength = outputLength;
    }

    public byte[] getZ()
    {
        return Arrays.clone(z);
    }

    /**
     * @return the salt, or null for the default salt.
     */
    public byte[] getSalt()
    {
        return Arrays.clone(salt);
    }

    public byte[] getFixedInfo()
    {
        return Arrays.clone(fixedInfo);
    }

    public int getOutputLength()
    {
        return outputLength;
    }
}
