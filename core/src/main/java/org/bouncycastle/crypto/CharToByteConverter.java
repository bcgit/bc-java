package org.bouncycastle.crypto;

/**
 * Interface for a converter that produces a byte encoding for a char array.
 */
public interface CharToByteConverter
{
    /**
     * Return the type of the conversion.
     *
     * @return a type name for the conversion.
     */
    String getType();

    /**
     * Return a byte encoded representation of the passed in password.
     *
     * @param password the characters to encode.
     * @return a byte encoding of password.
     */
    byte[] convert(char[] password);
}
