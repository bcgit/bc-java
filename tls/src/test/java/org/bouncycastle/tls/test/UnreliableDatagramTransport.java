package org.bouncycastle.tls.test;

import java.io.IOException;
import java.util.Random;

import org.bouncycastle.tls.DatagramTransport;

public class UnreliableDatagramTransport
    implements DatagramTransport
{

    private final DatagramTransport transport;
    private final Random random;
    private final int percentPacketLossReceiving, percentPacketLossSending;

    public UnreliableDatagramTransport(DatagramTransport transport, Random random,
                                       int percentPacketLossReceiving, int percentPacketLossSending)
    {
        if (percentPacketLossReceiving < 0 || percentPacketLossReceiving > 100)
        {
            throw new IllegalArgumentException("'percentPacketLossReceiving' out of range");
        }
        if (percentPacketLossSending < 0 || percentPacketLossSending > 100)
        {
            throw new IllegalArgumentException("'percentPacketLossSending' out of range");
        }

        this.transport = transport;
        this.random = random;
        this.percentPacketLossReceiving = percentPacketLossReceiving;
        this.percentPacketLossSending = percentPacketLossSending;
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
        for (; ; )
        {
            int length = transport.receive(buf, off, len, waitMillis);
            if (length < 0 || !lostPacket(percentPacketLossReceiving))
            {
                return length;
            }

            System.out.println("PACKET LOSS (" + length + " byte packet not received)");

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
        if (lostPacket(percentPacketLossSending))
        {
            System.out.println("PACKET LOSS (" + len + " byte packet not sent)");
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

    private boolean lostPacket(int percentPacketLoss)
    {
        return percentPacketLoss > 0 && random.nextInt(100) < percentPacketLoss;
    }
}
