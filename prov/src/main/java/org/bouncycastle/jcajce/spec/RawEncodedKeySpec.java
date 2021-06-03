package org.bouncycastle.jcajce.spec;

import java.security.spec.EncodedKeySpec;

/**
 * An encoded key spec that just wraps the minimal data for a public/private key representation.
 */
public class RawEncodedKeySpec
    extends EncodedKeySpec
{
    /**
     * Base constructor - just the minimal data.
     *
     * @param bytes the public/private key data.
     */
    public RawEncodedKeySpec(byte[] bytes)
    {
        super(bytes);
    }

    public String getFormat()
    {
        return "RAW";
    }
}
