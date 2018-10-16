package org.bouncycastle.jce.spec;

import java.security.spec.EncodedKeySpec;

public class OpenSSHPrivateKeySpec
    extends EncodedKeySpec

{
    private final String format;

    public OpenSSHPrivateKeySpec(byte[] encodedKey)
    {
        super(encodedKey);
        this.format = "raw";
    }


    public OpenSSHPrivateKeySpec(byte[] encodedKey, String format)
    {
        super(encodedKey);
        this.format = format;
    }

    public String getFormat()
    {
        return format;
    }
}
