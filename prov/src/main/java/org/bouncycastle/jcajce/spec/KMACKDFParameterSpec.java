package org.bouncycastle.jcajce.spec;

import java.security.spec.AlgorithmParameterSpec;

import org.bouncycastle.util.Arrays;

/**
 * Derivation parameters for the KMAC-based KDF of the CMS KEMRecipientInfo profiles (RFC 9629 with
 * id-Kmac128 / id-Kmac256, as used by RFC 9935 for ML-KEM): the derived key is
 * KMAC(secret, context, L, customization) with L the output length ({@code KDF.getInstance("KMAC128-KDF")}
 * or "KMAC256-KDF"). The customization is the Customization octet string the KDF's algorithm identifier
 * parameters may carry, empty when absent.
 */
public class KMACKDFParameterSpec
    implements AlgorithmParameterSpec
{
    private final byte[] secret;
    private final byte[] context;
    private final byte[] customization;
    private final int outputLength;

    public KMACKDFParameterSpec(byte[] secret, byte[] context, int outputLength)
    {
        this(secret, context, null, outputLength);
    }

    /**
     * @param secret        the KMAC key, the KEM shared secret in RFC 9629.
     * @param context       the KMAC message, the CMSORIforKEMOtherInfo encoding in RFC 9629; may be null.
     * @param customization the KMAC customization string, or null for none.
     * @param outputLength  the number of bytes to derive.
     */
    public KMACKDFParameterSpec(byte[] secret, byte[] context, byte[] customization, int outputLength)
    {
        if (secret == null)
        {
            throw new IllegalArgumentException("secret should not be null");
        }
        if (outputLength <= 0)
        {
            throw new IllegalArgumentException("outputLength must be positive");
        }
        this.secret = Arrays.clone(secret);
        this.context = (context == null) ? new byte[0] : Arrays.clone(context);
        this.customization = (customization == null) ? new byte[0] : Arrays.clone(customization);
        this.outputLength = outputLength;
    }

    public byte[] getSecret()
    {
        return Arrays.clone(secret);
    }

    public byte[] getContext()
    {
        return Arrays.clone(context);
    }

    public byte[] getCustomization()
    {
        return Arrays.clone(customization);
    }

    public int getOutputLength()
    {
        return outputLength;
    }
}
