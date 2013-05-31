package org.bouncycastle.crypto.tls;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public class NewSessionTicket
{

    protected long ticketLifetimeHint;
    protected byte[] ticket;

    public NewSessionTicket(long ticketLifetimeHint, byte[] ticket)
    {
        this.ticketLifetimeHint = ticketLifetimeHint;
        this.ticket = ticket;
    }

    public long getTicketLifetimeHint()
    {
        return ticketLifetimeHint;
    }

    public byte[] getTicket()
    {
        return ticket;
    }

    public void encode(OutputStream output)
        throws IOException
    {
        TlsUtils.writeUint32(ticketLifetimeHint, output);
        TlsUtils.writeOpaque16(ticket, output);
    }

    public static NewSessionTicket parse(InputStream input)
        throws IOException
    {
        long ticketLifetimeHint = TlsUtils.readUint32(input);
        byte[] ticket = TlsUtils.readOpaque16(input);
        return new NewSessionTicket(ticketLifetimeHint, ticket);
    }
}
