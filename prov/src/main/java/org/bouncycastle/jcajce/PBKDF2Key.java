package org.bouncycastle.jcajce;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
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
    private final AlgorithmIdentifier prf;

    /**
     * Basic constructor for a password based key using PBKDF - secret key generation parameters will be passed separately.
     * No PRF is recorded, so a cipher deriving a key from this one uses HMAC-SHA512.
     *
     * @param password password to use.
     * @param converter converter to use for turning the password into bytes.
     */
    public PBKDF2Key(char[] password, CharToByteConverter converter)
    {
        this(password, converter, null);
    }

    /**
     * Constructor for a password based key using PBKDF2 with a given PRF - secret key generation parameters will be
     * passed separately.
     *
     * @param password password to use.
     * @param converter converter to use for turning the password into bytes.
     * @param prf the PRF to use with PBKDF2, null if none is specified.
     */
    public PBKDF2Key(char[] password, CharToByteConverter converter, AlgorithmIdentifier prf)
    {
        this.password = Arrays.clone(password);
        this.converter = converter;
        this.prf = prf;
    }

    /**
     * Return the PRF to use with PBKDF2.
     *
     * @return the PRF's AlgorithmIdentifier, null if none was specified.
     */
    public AlgorithmIdentifier getPrf()
    {
        return prf;
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
