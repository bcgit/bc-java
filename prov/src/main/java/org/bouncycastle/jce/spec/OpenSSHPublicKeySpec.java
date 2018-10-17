package org.bouncycastle.jce.spec;

import java.security.spec.EncodedKeySpec;

public class OpenSSHPublicKeySpec
    extends EncodedKeySpec
{
    private static final String[] allowedTypes = new String[]{"ssh-rsa", "ssh-ed25519", "ssh-dss"};
    private final String type;

    public OpenSSHPublicKeySpec(byte[] encodedKey)
    {
        super(encodedKey);

        //
        // The type is encoded at the start of the blob.
        //
        int pos = 0;
        int i = (encodedKey[pos++] & 0xFF) << 24;
        i |= (encodedKey[pos++] & 0xFF) << 16;
        i |= (encodedKey[pos++] & 0xFF) << 8;
        i |= (encodedKey[pos++] & 0xFF);

        if (i >= encodedKey.length)
        {
            throw new IllegalArgumentException("invalid public key blob, type field longer than blob");
        }

        this.type = new String(encodedKey, pos, i);

        if (type.startsWith("ecdsa"))
        {
            return; // These have a curve name and digest in them and can't be compared exactly.
        }

        for (int t = 0; t < allowedTypes.length; t++)
        {
            if (allowedTypes[t].equals(this.type))
            {
                return;
            }
        }

        throw new IllegalArgumentException("unrecognised public key type " + type);

    }

    public String getFormat()
    {
        return "OpenSSH";
    }

    public String getType()
    {
        return type;
    }
}
