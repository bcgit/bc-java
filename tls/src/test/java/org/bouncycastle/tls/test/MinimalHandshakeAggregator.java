package org.bouncycastle.tls.test;

import java.io.IOException;

import org.bouncycastle.tls.ContentType;
import org.bouncycastle.tls.DatagramTransport;
import org.bouncycastle.tls.HandshakeType;
import org.bouncycastle.tls.TlsUtils;

/**
 * A very minimal and stupid class to aggregate DTLS handshake messages.  Only sufficient for unit tests.
 */
public class MinimalHandshakeAggregator
    implements DatagramTransport
{
    private final DatagramTransport transport;

    private final boolean aggregateReceiving, aggregateSending;

    byte[] receiveBuf, sendBuf;

    int receiveRecordCount, sendRecordCount;

    private byte[] addToBuf(byte[] baseBuf, byte[] buf, int off, int len)
    {
        byte[] ret = new byte[baseBuf.length + len];
        System.arraycopy(baseBuf, 0, ret, 0, baseBuf.length);
        System.arraycopy(buf, off, ret, baseBuf.length, len);
        return ret;
    }

    private void addToReceiveBuf(byte[] buf, int off, int len)
    {
        receiveBuf = addToBuf(receiveBuf, buf, off, len);
        receiveRecordCount++;
    }

    private void resetReceiveBuf()
    {
        receiveBuf = new byte[0];
        receiveRecordCount = 0;
    }

    private void addToSendBuf(byte[] buf, int off, int len)
    {
        sendBuf = addToBuf(sendBuf, buf, off, len);
        sendRecordCount++;
    }

    private void resetSendBuf()
    {
        sendBuf = new byte[0];
        sendRecordCount = 0;
    }

    /** Whether the buffered aggregated data should be flushed after this packet.
     * This is done on the end of the first flight - ClientHello and ServerHelloDone - and anything that is
     * Epoch 1.
     */
    private boolean flushAfterThisPacket(byte[] buf, int off, int len)
    {
        int epoch = TlsUtils.readUint16(buf, off + 3);
        if (epoch > 0)
        {
            return true;
        }
        short contentType = TlsUtils.readUint8(buf, off);
        if (ContentType.handshake != contentType)
        {
            return false;
        }
        short msgType = TlsUtils.readUint8(buf, off + 13);
        switch (msgType) {
        case HandshakeType.client_hello:
        case HandshakeType.server_hello_done:
            return true;
        default:
            return false;
        }
    }

    public MinimalHandshakeAggregator(DatagramTransport transport, boolean aggregateReceiving, boolean aggregateSending)
    {
        this.transport = transport;
        this.aggregateReceiving = aggregateReceiving;
        this.aggregateSending = aggregateSending;
        resetReceiveBuf();
        resetSendBuf();
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
            if (length < 0 || !aggregateReceiving)
            {
                return length;
            }

            addToReceiveBuf(buf, off, length);

            if (flushAfterThisPacket(buf, off, length)) {
                if (receiveRecordCount > 1)
                {
                    System.out.println("RECEIVING " + receiveRecordCount + " RECORDS IN " + length + " BYTE PACKET");
                }
                int resultLength = Math.min(len, receiveBuf.length);
                System.arraycopy(receiveBuf, 0, buf, off, resultLength);
                resetReceiveBuf();
                return resultLength;
            }

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
        if (!aggregateSending)
        {
            transport.send(buf, off, len);
            return;
        }
        addToSendBuf(buf, off, len);

        if (flushAfterThisPacket(buf, off, len))
        {
            if (sendRecordCount > 1)
            {
                System.out.println("SENDING " + sendRecordCount + " RECORDS IN " + sendBuf.length + " BYTE PACKET");
            }
            transport.send(sendBuf, 0, sendBuf.length);
            resetSendBuf();
        }
    }

    public void close()
        throws IOException
    {
        transport.close();
    }
}
