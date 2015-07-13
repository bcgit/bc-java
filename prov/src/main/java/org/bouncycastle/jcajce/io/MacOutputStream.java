package org.bouncycastle.jcajce.io;

import java.io.IOException;
import java.io.OutputStream;

import javax.crypto.Mac;

/**
 * An output stream which calculates a MAC based on the data that is written to it.
 */
public final class MacOutputStream
    extends OutputStream
{
    private Mac mac;

    /**
     * Base constructor - specify the MAC algorithm to use.
     *
     * @param mac the MAC implementation to use as the basis of the stream.
     */
    public MacOutputStream(
        Mac mac)
    {
        this.mac = mac;
    }

    /**
     * Write a single byte to the stream.
     *
     * @param b the byte value to write.
     * @throws IOException  in case of failure.
     */
    public void write(int b)
        throws IOException
    {
        mac.update((byte)b);
    }

    /**
     * Write a block of data of length len starting at offset off in the byte array bytes to
     * the stream.
     *
     * @param bytes byte array holding the data.
     * @param off offset into bytes that the data starts at.
     * @param len the length of the data block to write.
     * @throws IOException in case of failure.
     */
    public void write(
        byte[] bytes,
        int off,
        int len)
        throws IOException
    {
        mac.update(bytes, off, len);
    }

    /**
     * Execute doFinal() and return the calculated MAC.
     *
     * @return the MAC calculated from the output written to the stream.
     */
    public byte[] getMac()
    {
        return mac.doFinal();
    }
}
