package org.bouncycastle.jcajce.spec;

import java.security.spec.AlgorithmParameterSpec;

import org.bouncycastle.util.Arrays;

/**
 * ParameterSpec for the KMAC variants of SHAKE as used by CMS (RFC 8702 &sect;3.4).
 * Carries the MAC output length and the customization string {@code S} that are
 * encoded in the {@code KMACwithSHAKEnnn-params} SEQUENCE.
 */
public class KMACParameterSpec
    implements AlgorithmParameterSpec
{
    private final int macSizeInBits;
    private final byte[] customizationString;

    /**
     * Base constructor with empty customization string.
     *
     * @param macSizeInBits the requested MAC output length in bits; must be a multiple of 8.
     */
    public KMACParameterSpec(int macSizeInBits)
    {
        this(macSizeInBits, new byte[0]);
    }

    /**
     * Base constructor.
     *
     * @param macSizeInBits the requested MAC output length in bits; must be a multiple of 8.
     * @param customizationString the customization string {@code S} passed to KMAC; may be empty.
     */
    public KMACParameterSpec(int macSizeInBits, byte[] customizationString)
    {
        if ((macSizeInBits & 7) != 0)
        {
            throw new IllegalArgumentException("macSizeInBits must be a multiple of 8");
        }
        if (macSizeInBits <= 0)
        {
            throw new IllegalArgumentException("macSizeInBits must be positive");
        }

        this.macSizeInBits = macSizeInBits;
        this.customizationString = (customizationString == null) ? new byte[0] : Arrays.clone(customizationString);
    }

    public int getMacSizeInBits()
    {
        return macSizeInBits;
    }

    public byte[] getCustomizationString()
    {
        return Arrays.clone(customizationString);
    }
}
