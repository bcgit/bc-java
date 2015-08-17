package org.bouncycastle.jcajce;

import org.bouncycastle.crypto.CharToByteConverter;
import org.bouncycastle.util.Arrays;

/**
 * A password based key for use with PBKDF2 as defined in PKCS#5.
 */
public class PBKDF2Key
    implements PBKDFKey
{
    private final char[] password;
    private final CharToByteConverter converter;

    /**
     * Basic constructor for a password based key using PBKDF - secret key generation parameters will be passed separately..
     *
     * @param password password to use.
     */
    public PBKDF2Key(char[] password, CharToByteConverter converter)
    {
        this.password = Arrays.clone(password);
        this.converter = converter;
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
     * @return the string "PBKDF2"
     */
    public String getAlgorithm()
    {
        return "PBKDF2";
    }

    /**
     * Return the format encoding.
     *
     * @return the type name representing a char[] to byte[] conversion.
     */
    public String getFormat()
    {
        return converter.getType();
    }

    /**
     * Return the password converted to bytes.
     *
     * @return the password converted to a byte array.
     */
    public byte[] getEncoded()
    {
        return converter.convert(password);
    }
}
