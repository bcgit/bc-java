package org.bouncycastle.jcajce.spec;

import java.security.spec.EncodedKeySpec;

import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;

/**
 * Holds an OpenSSH encoded public key.
 */
public class OpenSSHPublicKeySpec
    extends EncodedKeySpec
{
    private static final String[] allowedTypes = new String[]{"ssh-rsa", "ssh-ed25519", "ssh-dss"};
    private final String type;


    /**
     * Construct and instance and determine the OpenSSH public key type.
     * The current types are ssh-rsa, ssh-ed25519, ssh-dss and ecdsa-*
     * <p>
     * It does not validate the key beyond identifying the type.
     *
     * @param encodedKey
     */
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

        if ((pos + i) >= encodedKey.length)
        {
            throw new IllegalArgumentException("invalid public key blob: type field longer than blob");
        }

        this.type = Strings.fromByteArray(Arrays.copyOfRange(encodedKey, pos, pos + i));

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

    /**
     * The type of OpenSSH public key.
     *
     * @return the type.
     */
    public String getType()
    {
        return type;
    }
}
