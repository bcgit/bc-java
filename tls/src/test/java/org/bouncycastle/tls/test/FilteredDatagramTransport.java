package org.bouncycastle.tls.test;

import java.io.IOException;

import org.bouncycastle.tls.DatagramTransport;

public class FilteredDatagramTransport
    implements DatagramTransport
{
    public interface FilterPredicate
    {
        boolean allowPacket(byte[] buf, int off, int len);
    }

    public static final FilterPredicate ALWAYS_ALLOW = new FilterPredicate()
    {
        public boolean allowPacket(byte[] buf, int off, int len)
        {
            return true;
        }
    };

    private final DatagramTransport transport;

    private final FilterPredicate allowReceiving, allowSending;

    public FilteredDatagramTransport(DatagramTransport transport, FilterPredicate allowReceiving,
        FilterPredicate allowSending)
    {
        this.transport = transport;
        this.allowReceiving = allowReceiving;
        this.allowSending = allowSending;
    }

    public int getReceiveLimit()
        throws IOException
    {
        return transport.getReceiveLimit();
    }

    public int getSendLimit()
        throws IOException
    {
        return transport.getSendLimit();
    }

    public int receive(byte[] buf, int off, int len, int waitMillis)
        throws IOException
    {
        long endMillis = System.currentTimeMillis() + waitMillis;
        for (;;)
        {
            int length = transport.receive(buf, off, len, waitMillis);
            if (length < 0 || allowReceiving.allowPacket(buf, off, len))
            {
                return length;
            }

            System.out.println("PACKET FILTERED (" + length + " byte packet not received)");

            long now = System.currentTimeMillis();
            if (now >= endMillis)
            {
                return -1;
            }

            waitMillis = (int)(endMillis - now);
        }
    }

    public void send(byte[] buf, int off, int len)
        throws IOException
    {
        if (!allowSending.allowPacket(buf, off, len))
        {
            System.out.println("PACKET FILTERED (" + len + " byte packet not sent)");
        }
        else
        {
            transport.send(buf, off, len);
        }
    }

    public void close()
        throws IOException
    {
        transport.close();
    }
}
