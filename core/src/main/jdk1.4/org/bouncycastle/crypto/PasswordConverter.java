package org.bouncycastle.crypto;

/**
 * Standard char[] to byte[] converters for password based derivation algorithms.
 */
public final class PasswordConverter
{
    /**
     * Do a straight char[] to 8 bit conversion.
     */
    public static final CharToByteConverter ASCII = new CharToByteConverter()
    {
        public String getType()
        {
            return "ASCII";
        }

        public byte[] convert(char[] password)
        {
            return PBEParametersGenerator.PKCS5PasswordToBytes(password);
        }
    };

    /**
     * Do a char[] conversion by producing UTF-8 data.
     */
    public static final CharToByteConverter UTF8 = new CharToByteConverter()
    {
        public String getType()
        {
            return "UTF8";
        }

        public byte[] convert(char[] password)
        {
            return PBEParametersGenerator.PKCS5PasswordToUTF8Bytes(password);
        }
    };

    /**
     * Do char[] to BMP conversion (i.e. 2 bytes per character).
     */
    public static final CharToByteConverter PKCS12 = new CharToByteConverter()
    {
        public String getType()
        {
            return "PKCS12";
        }

        public byte[] convert(char[] password)
        {
            return PBEParametersGenerator.PKCS12PasswordToBytes(password);
        }
    };
}
