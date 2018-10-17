package org.bouncycastle.jce.spec;

import java.security.spec.EncodedKeySpec;

public class OpenSSHPrivateKeySpec
    extends EncodedKeySpec
{
    private final String format;

    public OpenSSHPrivateKeySpec(byte[] encodedKey)
    {
        super(encodedKey);

        if  (encodedKey[0] == 0x30)   // DER SEQUENCE
        {
            format = "ASN.1";
        }
        else if (encodedKey[0] == 'o')
        {
            format = "OpenSSH";
        }
        else
        {
            throw new IllegalArgumentException("unknown byte encoding");
        }
    }

    public String getFormat()
    {
        return format;
    }
}
