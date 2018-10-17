package org.bouncycastle.jce.spec;

import java.security.spec.EncodedKeySpec;

import org.bouncycastle.crypto.util.OpenSSHPrivateKeyUtil;

/**
 * OpenSSHPrivateKeySpec holds and encoded OpenSSH private key.
 * The format of the key can be either ASN.1 or OpenSSH.
 */
public class OpenSSHPrivateKeySpec
    extends EncodedKeySpec

{
    private final String format;

    /**
     * Accept an encoded key and determine the format.
     * <p>
     * The encoded key should be the Base64 decoded blob between the "---BEGIN and ---END" markers.
     * This constructor will endeavour to find the OpenSSH format magic value. If it can not then it
     * will default to ASN.1. It does not attempt to validate the ASN.1
     * <p>
     * Example:
     * OpenSSHPrivateKeySpec privSpec = new OpenSSHPrivateKeySpec(rawPriv);
     * <p>
     * KeyFactory kpf = KeyFactory.getInstance("RSA", "BC");
     * PrivateKey prk = kpf.generatePrivate(privSpec);
     * <p>
     * OpenSSHPrivateKeySpec rcPrivateSpec = kpf.getKeySpec(prk, OpenSSHPrivateKeySpec.class);
     *
     * @param encodedKey The encoded key.
     */
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

    /**
     * Return the format, either OpenSSH for the OpenSSH propriety format or ASN.1.
     *
     * @return the format OpenSSH or ASN.1
     */
    public String getFormat()
    {
        return format;
    }
}
