package org.bouncycastle.jcajce.spec;

import java.security.spec.EncodedKeySpec;

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
