package org.bouncycastle.jcajce;

import javax.crypto.SecretKey;

import org.bouncycastle.crypto.PBEParametersGenerator;
import org.bouncycastle.jcajce.provider.keystore.PKCS12;

public class PKCS12Key
    implements SecretKey
{
    private final char[] password;
    private final boolean useWrongZeroLengthConversion;
    /**
     * Basic constructor for a password based key - secret key generation parameters will be passed separately..
     *
     * @param password password to use.
     */
    public PKCS12Key(char[] password)
    {
        this(password, false);
    }

    /**
     * Unfortunately there seems to be some confusion about how to handle zero length
     * passwords.
     *
     * @param password password to use.
     * @param useWrongZeroLengthConversion use the incorrect encoding approach (add pad bytes)
     */
    public PKCS12Key(char[] password, boolean useWrongZeroLengthConversion)
    {
        this.password = new char[password.length];
        this.useWrongZeroLengthConversion = useWrongZeroLengthConversion;

        System.arraycopy(password, 0, this.password, 0, password.length);
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
        if (useWrongZeroLengthConversion && password.length == 0)
        {
            return new byte[2];
        }

        return PBEParametersGenerator.PKCS12PasswordToBytes(password);
    }
}
