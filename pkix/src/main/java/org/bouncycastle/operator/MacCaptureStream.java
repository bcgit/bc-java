package org.bouncycastle.operator;

import java.io.IOException;
import java.io.OutputStream;

import org.bouncycastle.util.Arrays;

/**
 * A generic class for capturing the mac data at the end of a encrypted data stream.
 * <p>
 * Note: this class will not close the underlying stream.
 * </p>
 */
public class MacCaptureStream
    extends OutputStream
{
    private final OutputStream cOut;
    private final byte[] mac;

    int macIndex = 0;

    public MacCaptureStream(OutputStream cOut, int macLength)
    {
        this.cOut = cOut;
        this.mac = new byte[macLength];
    }

    public void write(byte[] buf, int off, int len)
        throws IOException
    {
        if (len >= mac.length)
        {
            cOut.write(mac, 0, macIndex);
            macIndex = mac.length;
            System.arraycopy(buf, off + len - mac.length, mac, 0, mac.length);
            cOut.write(buf, off, len - mac.length);
        }
        else
        {
            for (int i = 0; i != len; i++)
            {
                write(buf[off + i]);
            }
        }
    }

    public void write(int b)
        throws IOException
    {
        if (macIndex == mac.length)
        {
             byte b1 = mac[0];
             System.arraycopy(mac, 1, mac, 0, mac.length - 1);
             mac[mac.length - 1] = (byte)b;
             cOut.write(b1);
        }
        else
        {
            mac[macIndex++] = (byte)b;
        }
    }

    public byte[] getMac()
    {
        return Arrays.clone(mac);
    }
}
