package org.bouncycastle.jsse.provider.gm;

import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.tls.Certificate;
import org.bouncycastle.tls.TlsClientProtocol;
import org.bouncycastle.tls.TlsProtocol;
import org.bouncycastle.tls.TlsServerProtocol;
import org.bouncycastle.tls.crypto.TlsCrypto;

import javax.net.ssl.HandshakeCompletedListener;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.net.SocketAddress;
import java.net.SocketException;
import java.nio.channels.SocketChannel;

/**
 * GMSSL Socket simple implement.
 *
 * @author Cliven
 * @since 2021-03-16 13:18:06
 */
public class GMSimpleSSLSocketWrap extends GMSimpleSSLSocket
{
    protected Socket wrapScoket = null;
    protected boolean autoClose;

    public GMSimpleSSLSocketWrap(Socket wrapScoket, boolean autoClose)
    {
        super();
        this.wrapScoket = wrapScoket;
        this.autoClose = autoClose;
    }

    @Override
    public void connect(SocketAddress endpoint) throws IOException
    {
        throw new SocketException("Wrapped socket should already be connected");
    }

    @Override
    public void connect(SocketAddress endpoint, int timeout) throws IOException
    {
        throw new SocketException("Wrapped socket should already be connected");
    }

    @Override
    public void bind(SocketAddress bindpoint) throws IOException
    {
        wrapScoket.bind(bindpoint);
    }

    @Override
    public InetAddress getInetAddress()
    {
        return wrapScoket.getInetAddress();
    }

    @Override
    public InetAddress getLocalAddress()
    {
        return wrapScoket.getLocalAddress();
    }

    @Override
    public int getPort()
    {
        return wrapScoket.getPort();
    }

    @Override
    public int getLocalPort()
    {
        return wrapScoket.getLocalPort();
    }

    @Override
    public SocketAddress getRemoteSocketAddress()
    {
        return wrapScoket.getRemoteSocketAddress();
    }

    @Override
    public SocketAddress getLocalSocketAddress()
    {
        return wrapScoket.getLocalSocketAddress();
    }

    @Override
    public SocketChannel getChannel()
    {
        return wrapScoket.getChannel();
    }

    @Override
    public void setTcpNoDelay(boolean on) throws SocketException
    {
        wrapScoket.setTcpNoDelay(on);
    }

    @Override
    public boolean getTcpNoDelay() throws SocketException
    {
        return wrapScoket.getTcpNoDelay();
    }

    @Override
    public void setSoLinger(boolean on, int linger) throws SocketException
    {
        wrapScoket.setSoLinger(on, linger);
    }

    @Override
    public int getSoLinger() throws SocketException
    {
        return wrapScoket.getSoLinger();
    }

    @Override
    public void sendUrgentData(int data) throws IOException
    {
        wrapScoket.sendUrgentData(data);
    }

    @Override
    public void setOOBInline(boolean on) throws SocketException
    {
        wrapScoket.setOOBInline(on);
    }

    @Override
    public boolean getOOBInline() throws SocketException
    {
        return wrapScoket.getOOBInline();
    }

    @Override
    public synchronized void setSoTimeout(int timeout) throws SocketException
    {
        wrapScoket.setSoTimeout(timeout);
    }

    @Override
    public synchronized int getSoTimeout() throws SocketException
    {
        return wrapScoket.getSoTimeout();
    }

    @Override
    public synchronized void setSendBufferSize(int size) throws SocketException
    {
        wrapScoket.setSendBufferSize(size);
    }

    @Override
    public synchronized int getSendBufferSize() throws SocketException
    {
        return wrapScoket.getSendBufferSize();
    }

    @Override
    public synchronized void setReceiveBufferSize(int size) throws SocketException
    {
        wrapScoket.setReceiveBufferSize(size);
    }

    @Override
    public synchronized int getReceiveBufferSize() throws SocketException
    {
        return wrapScoket.getReceiveBufferSize();
    }

    @Override
    public void setKeepAlive(boolean on) throws SocketException
    {
        wrapScoket.setKeepAlive(on);
    }

    @Override
    public boolean getKeepAlive() throws SocketException
    {
        return wrapScoket.getKeepAlive();
    }

    @Override
    public void setTrafficClass(int tc) throws SocketException
    {
        wrapScoket.setTrafficClass(tc);
    }

    @Override
    public int getTrafficClass() throws SocketException
    {
        return wrapScoket.getTrafficClass();
    }

    @Override
    public void setReuseAddress(boolean on) throws SocketException
    {
        wrapScoket.setReuseAddress(on);
    }

    @Override
    public boolean getReuseAddress() throws SocketException
    {
        return wrapScoket.getReuseAddress();
    }

    @Override
    public void shutdownInput() throws IOException
    {
        wrapScoket.shutdownInput();
    }

    @Override
    public void shutdownOutput() throws IOException
    {
        wrapScoket.shutdownOutput();
    }

    @Override
    public String toString()
    {
        return wrapScoket.toString();
    }

    @Override
    public boolean isConnected()
    {
        return wrapScoket.isConnected();
    }

    @Override
    public boolean isBound()
    {
        return wrapScoket.isBound();
    }

    @Override
    public boolean isClosed()
    {
        return wrapScoket.isClosed();
    }

    @Override
    public boolean isInputShutdown()
    {
        return wrapScoket.isInputShutdown();
    }

    @Override
    public boolean isOutputShutdown()
    {
        return wrapScoket.isOutputShutdown();
    }

    @Override
    public void setPerformancePreferences(int connectionTime, int latency, int bandwidth)
    {
        wrapScoket.setPerformancePreferences(connectionTime, latency, bandwidth);
    }

    @Override
    public void startHandshake() throws IOException
    {
        makeHandshake(wrapScoket.getInputStream(), wrapScoket.getOutputStream());
    }
    @Override
    public synchronized void close() throws IOException
    {
        super.close();
        if(autoClose)
        {
            wrapScoket.close();
        }
    }

}
