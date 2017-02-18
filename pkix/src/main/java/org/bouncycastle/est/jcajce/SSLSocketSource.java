package org.bouncycastle.est.jcajce;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;

import org.bouncycastle.est.Source;


public class SSLSocketSource
    implements Source<SSLSession, byte[]>
{
    protected final SSLSocket socket;
    private final ChannelBindingProvider bindingProvider;

    public SSLSocketSource(SSLSocket sock, ChannelBindingProvider bindingProvider)
    {
        this.socket = sock;
        this.bindingProvider = bindingProvider;
    }

    public InputStream getInputStream()
        throws IOException
    {
        return socket.getInputStream();
    }

    public OutputStream getOutputStream()
        throws IOException
    {
        return socket.getOutputStream();
    }

    public SSLSession getSession()
    {
        return socket.getSession();
    }

    public byte[] getTLSUnique()
    {
        if (bindingProvider != null) {
           return  bindingProvider.getChannelBinding(socket,"tls-unique");
        }
        throw new IllegalArgumentException("No binding provider.");
    }

    public boolean isTLSUniqueAvailable()
    {
        if (bindingProvider == null) {
            return false;
        }
        return bindingProvider.canAccessChannelBinding(socket);
    }

    public void close()
        throws IOException
    {
        socket.close();
    }
}
