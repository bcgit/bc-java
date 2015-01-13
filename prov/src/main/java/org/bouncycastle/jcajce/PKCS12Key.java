package org.bouncycastle.jcajce;

import javax.crypto.SecretKey;

import org.bouncycastle.crypto.PBEParametersGenerator;

public class PKCS12Key
    implements SecretKey
{
    private final char[] password;

    /**
     * Basic constructor for a password based key - secret key generation parameters will be passed separately..
     *
     * @param password password to use.
     */
    public PKCS12Key(char[] password)
    {
        this.password = password.clone();
    }

    public char[] getPassword()
    {
        return password;
    }

    public String getAlgorithm()
    {
        return "PKCS12";
    }

    public String getFormat()
    {
        return "RAW";
    }

    public byte[] getEncoded()
    {
        return PBEParametersGenerator.PKCS12PasswordToBytes(password);
    }
}
