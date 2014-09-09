package org.bouncycastle.util;

import java.io.IOException;

/**
 * Interface implemented by objects that can be converted into byte arrays.
 */
public interface Encodable
{
    /**
     * Return a byte array representing the implementing object.
     *
     * @return a byte array representing the encoding.
     * @throws java.io.IOException if an issue arises generation the encoding.
     */
    byte[] getEncoded()
        throws IOException;
}
