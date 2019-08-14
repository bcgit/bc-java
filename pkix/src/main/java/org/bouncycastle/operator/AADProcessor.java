package org.bouncycastle.operator;

import java.io.OutputStream;

/**
 * Base interface for extra methods required for handling associated data in AEAD ciphers.
 */
public interface AADProcessor
{
    /**
     * Return a stream to write associated data to in order to have it incorporated into the
     * AEAD cipher's MAC.
     *
     * @return a stream for collecting associated data.
     */
    OutputStream getAADStream();

    /**
     * Return the final value of AEAD cipher's MAC.
     *
     * @return MAC value for the AEAD cipher.
     */
    byte[] getMAC();
}
