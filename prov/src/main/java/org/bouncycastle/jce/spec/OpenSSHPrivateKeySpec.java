package org.bouncycastle.jce.spec;

import java.security.spec.EncodedKeySpec;

public class OpenSSHPrivateKeySpec
    extends EncodedKeySpec

{
    public OpenSSHPrivateKeySpec(byte[] encodedKey)
    {
        super(encodedKey);
    }

    public String getFormat()
    {
        return "OpenSSH";
    }
}
