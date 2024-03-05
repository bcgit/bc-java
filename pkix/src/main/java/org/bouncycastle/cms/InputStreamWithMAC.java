package org.bouncycastle.cms;

import java.io.IOException;
import java.io.InputStream;

import org.bouncycastle.util.Arrays;

public final class InputStreamWithMAC
    extends InputStream
{
    private final InputStream base;
    private MACProvider macProvider;
    private byte[] mac;
    private boolean baseFinished;
    private int index;

    InputStreamWithMAC(InputStream base, MACProvider macProvider)
    {
        this.base = base;
        this.macProvider = macProvider;

        baseFinished = false;
        index = 0;
    }

    public InputStreamWithMAC(InputStream base, byte[] mac)
    {
        this.base = base;
        this.mac = mac;
        baseFinished = false;
        index = 0;
    }

    @Override
    public int read()
        throws IOException
    {
        int ch;
        if (!baseFinished)
        {
            ch = base.read();
            if (ch < 0)
            {
                baseFinished = true;
                if (macProvider != null)
                {
                    macProvider.init();
                    mac = macProvider.getMAC();
                }
                return mac[index++] & 0xFF;
            }
        }
        else
        {
            if (index >= mac.length)
            {
                return -1;
            }
            return mac[index++] & 0xFF;
        }
        return ch;
    }

    public byte[] getMAC()
    {
        if (!baseFinished)
        {
            throw new IllegalStateException("input stream not fully processed");
        }
        return Arrays.clone(mac);
    }

    @Override
    public int read(byte[] b, int off, int len)
        throws IOException
    {
        if (b == null)
        {
            throw new NullPointerException("input array is null");
        }
        if (off < 0 || b.length < off + len)
        {
            throw new IndexOutOfBoundsException("invalid off(" + off + ") and len(" + len + ")");
        }
        int ch;
        if (!baseFinished)
        {
            ch = base.read(b, off, len);
            if (ch < 0)
            {
                baseFinished = true;
                if (macProvider != null)
                {
                    macProvider.init();
                    mac = macProvider.getMAC();
                }
                if (len >= mac.length)
                {
                    System.arraycopy(mac, 0, b, off, mac.length);
                    index = mac.length;
                    return mac.length;
                }
                else
                {
                    System.arraycopy(mac, 0, b, off, len);
                    index += len;
                    return len;
                }
            }
            return ch;
        }
        else if (index < mac.length)
        {
            if (len >= mac.length - index)
            {
                System.arraycopy(mac, index, b, off, mac.length - index);
                int tmp = mac.length - index;
                index = mac.length;
                return tmp;
            }
            else
            {
                System.arraycopy(mac, index, b, off, len);
                index += len;
                return len;
            }
        }
        return -1;
    }
}

