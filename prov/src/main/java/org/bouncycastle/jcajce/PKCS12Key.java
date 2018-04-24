package org.bouncycastle.jcajce;

import org.bouncycastle.crypto.PBEParametersGenerator;

/**
 * A password based key for use with PKCS#12.
 */
public class PKCS12Key
    implements PBKDFKey
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
        if (password == null)
        {
            password = new char[0];
        }

        this.password = new char[password.length];
        this.useWrongZeroLengthConversion = useWrongZeroLengthConversion;

        System.arraycopy(password, 0, this.password, 0, password.length);
    }

    /**
     * Return a reference to the char[] array holding the password.
     *
     * @return a reference to the password array.
     */
    public char[] getPassword()
    {
        return password;
    }

    /**
     * Return the password based key derivation function this key is for,
     *
     * @return the string "PKCS12"
     */
    public String getAlgorithm()
    {
        return "PKCS12";
    }

    /**
     * Return the format encoding.
     *
     * @return the string "PKCS12", representing the char[] to byte[] conversion.
     */
    public String getFormat()
    {
        return "PKCS12";
    }

    /**
     * Return the password converted to bytes.
     *
     * @return the password converted to a byte array.
     */
    public byte[] getEncoded()
    {
        if (useWrongZeroLengthConversion && password.length == 0)
        {
            return new byte[2];
        }

        return PBEParametersGenerator.PKCS12PasswordToBytes(password);
    }
}
