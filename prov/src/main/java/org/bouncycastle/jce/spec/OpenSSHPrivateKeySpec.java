package org.bouncycastle.jce.spec;

import java.security.spec.EncodedKeySpec;

import org.bouncycastle.crypto.util.OpenSSHPrivateKeyUtil;

public class OpenSSHPrivateKeySpec
    extends EncodedKeySpec

{
    private final String format;

    public OpenSSHPrivateKeySpec(byte[] encodedKey)
    {

        super(encodedKey);

        boolean openssh = true;

        for (int t = 0; t < OpenSSHPrivateKeyUtil.AUTH_MAGIC.length; t++)
        {
            if (encodedKey[t] != OpenSSHPrivateKeyUtil.AUTH_MAGIC[t])
            {
                openssh = false;
                break;
            }
        }

        format = openssh ? "OpenSSH" : "ASN.1";

    }

    public String getFormat()
    {
        return format;
    }
}
