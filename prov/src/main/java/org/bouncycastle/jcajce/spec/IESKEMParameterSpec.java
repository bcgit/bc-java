package org.bouncycastle.jcajce.spec;

import java.security.spec.AlgorithmParameterSpec;

import org.bouncycastle.util.Arrays;

/**
 * Parameter spec for an integrated encryptor KEM, as in IEEE_Std_1609_2
 */
public class IESKEMParameterSpec
    implements AlgorithmParameterSpec
{
    private final byte[] recipientInfo;
    private final boolean usePointCompression;


    /**
     * Set the IESKEM parameters.
     *
     * @param recipientInfo recipient data.
     */
    public IESKEMParameterSpec(
        byte[] recipientInfo)
    {
        this(recipientInfo, false);
    }

    /**
     * Set the IESKEM parameters - specifying point compression.
     *
     * @param recipientInfo recipient data.
     * @param usePointCompression use point compression on output (ignored on input).
     */
    public IESKEMParameterSpec(
        byte[] recipientInfo,
        boolean usePointCompression)
    {
        this.recipientInfo = Arrays.clone(recipientInfo);
        this.usePointCompression = usePointCompression;
    }

    public byte[] getRecipientInfo()
    {
        return Arrays.clone(recipientInfo);
    }

    public boolean hasUsePointCompression()
    {
        return usePointCompression;
    }
}