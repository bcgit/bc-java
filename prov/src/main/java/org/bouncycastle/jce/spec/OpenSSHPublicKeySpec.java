package org.bouncycastle.jce.spec;

import java.security.spec.EncodedKeySpec;

public class OpenSSHPublicKeySpec
    extends EncodedKeySpec
{
    public OpenSSHPublicKeySpec(byte[] encodedKey)
    {
        super(encodedKey);
    }

    public String getFormat()
    {
        return "raw";
    }
}
