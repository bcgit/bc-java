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
    private final char[] password;

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
        this(encodedKey, null);
    }

    /**
     * Accept an encoded key, determine the format, and carry the passphrase used to decrypt a
     * passphrase-protected openssh-key-v1 key.
     * <p>
     * Only the openssh-key-v1 format supports encryption; for an unencrypted key (or the ASN.1
     * format) the password is ignored and may be {@code null}. The password characters are used
     * as their UTF-8 bytes, matching the OpenSSH client.
     *
     * @param encodedKey The encoded key.
     * @param password   The passphrase, or {@code null} for an unencrypted key.
     */
    public OpenSSHPrivateKeySpec(byte[] encodedKey, char[] password)
    {
        super(encodedKey);

        this.password = password;

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

    /**
     * Return the passphrase used to decrypt an encrypted openssh-key-v1 key, or {@code null}
     * if none was supplied.
     *
     * @return the passphrase, or {@code null}.
     */
    public char[] getPassword()
    {
        return password;
    }
}
