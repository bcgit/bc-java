package org.bouncycastle.tls.test;

import java.io.IOException;
import java.io.PrintStream;

import org.bouncycastle.tls.DatagramTransport;
import org.bouncycastle.util.Strings;

public class LoggingDatagramTransport
    implements DatagramTransport
{

    private static final String HEX_CHARS = "0123456789ABCDEF";

    private final DatagramTransport transport;
    private final PrintStream output;
    private final long launchTimestamp;

    public LoggingDatagramTransport(DatagramTransport transport, PrintStream output)
    {
        this.transport = transport;
        this.output = output;
        this.launchTimestamp = System.currentTimeMillis();
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
        int length = transport.receive(buf, off, len, waitMillis);
        if (length >= 0)
        {
            dumpDatagram("Received", buf, off, length);
        }
        return length;
    }

    public void send(byte[] buf, int off, int len)
        throws IOException
    {
        dumpDatagram("Sending", buf, off, len);
        transport.send(buf, off, len);
    }

    public void close()
        throws IOException
    {
    }

    private void dumpDatagram(String verb, byte[] buf, int off, int len)
        throws IOException
    {
        long timestamp = System.currentTimeMillis() - launchTimestamp;
        StringBuffer sb = new StringBuffer("(+" + timestamp + "ms) " + verb + " " + len + " byte datagram:");
        for (int pos = 0; pos < len; ++pos)
        {
            if (pos % 16 == 0)
            {
                sb.append(Strings.lineSeparator());
                sb.append("    ");
            }
            else if (pos % 16 == 8)
            {
                sb.append('-');
            }
            else
            {
                sb.append(' ');
            }
            int val = buf[off + pos] & 0xFF;
            sb.append(HEX_CHARS.charAt(val >> 4));
            sb.append(HEX_CHARS.charAt(val & 0xF));
        }
        dump(sb.toString());
    }

    private synchronized void dump(String s)
    {
        output.println(s);
    }
}
