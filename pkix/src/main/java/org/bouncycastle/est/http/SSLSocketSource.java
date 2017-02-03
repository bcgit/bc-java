package org.bouncycastle.est.http;

import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;


public class SSLSocketSource implements Source<SSLSession>
{
    protected final SSLSocket socket;

    public SSLSocketSource(SSLSocket sock)
    {
        this.socket = sock;
    }

    public InputStream getInputStream() throws IOException
    {
        return socket.getInputStream();
    }

    public OutputStream getOutputStream() throws IOException
    {
        return socket.getOutputStream();
    }

    public SSLSession getSession()
    {
        return socket.getSession();
    }

    public void close() throws IOException
    {
        socket.close();
    }
}
