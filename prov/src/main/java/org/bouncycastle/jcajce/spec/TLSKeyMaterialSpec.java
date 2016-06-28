package org.bouncycastle.jcajce.spec;

import java.security.spec.KeySpec;

import org.bouncycastle.util.Arrays;

/**
 * Key Spec class for generating TLS key/iv material.
 */
public class TLSKeyMaterialSpec
    implements KeySpec
{
    public static final String MASTER_SECRET = "master secret";
    public static final String KEY_EXPANSION = "key expansion";

    private final byte[] secret;
    private final String label;
    private final int length;
    private final byte[] seed;

    /**
     * Constructor specifying the basic parameters for a TLS KDF
     *
     * @param secret secret to use
     * @param label e.g. 'master secret', or 'key expansion'
     * @param length number of bytes of material to be generated
     * @param seedMaterial array of seed material inputs (to be concatenated together)
     */
    public TLSKeyMaterialSpec(byte[] secret, String label, int length, byte[]... seedMaterial)
    {
        this.secret = Arrays.clone(secret);
        this.label = label;
        this.length = length;
        this.seed = Arrays.concatenate(seedMaterial);
    }

    /**
     * Return the label associated with this spec.
     *
     * @return the label to be used with the TLS KDF.
     */
    public String getLabel()
    {
        return label;
    }

    /**
     * Return the number of bytes of key material to be generated for this spec.
     *
     * @return the length in bytes of the result.
     */
    public int getLength()
    {
        return length;
    }

    /**
     * Return the secret associated with this spec.
     *
     * @return a copy of the secret.
     */
    public byte[] getSecret()
    {
        return Arrays.clone(secret);
    }

    /**
     * Return the full seed for the spec.
     *
     * @return a copy of the seed.
     */
    public byte[] getSeed()
    {
        return Arrays.clone(seed);
    }
}
