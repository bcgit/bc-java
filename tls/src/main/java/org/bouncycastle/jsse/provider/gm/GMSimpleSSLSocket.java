package org.bouncycastle.jsse.provider.gm;

import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.tls.*;
import org.bouncycastle.tls.crypto.TlsCrypto;

import javax.net.ssl.HandshakeCompletedListener;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.SocketAddress;

/**
 * GMSSL Socket simple implement.
 *
 *
 * @since 2021-03-16 13:18:06
 */
public class GMSimpleSSLSocket extends SSLSocket
{
    public static final String[] SUPPORT_CRYPTO_SUITES = {
            "GMSSL_SM2_SM4_SM3"
    };

    public static final String[] SUPPORT_PROTOCOL_VERSIONS = {
            "GMSSLv1.1"
    };

    protected boolean useClientMode = true;
    private TlsProtocol protocol;

    protected TlsCrypto crypto;
    protected Certificate certList;
    protected AsymmetricKeyParameter signKey, encKey;

    private GMSession session;


    protected GMSimpleSSLSocket()
    {
        super();
    }

    public GMSimpleSSLSocket(String host, int port) throws IOException
    {
        super(host, port);
    }

    public GMSimpleSSLSocket(InetAddress host, int port) throws IOException
    {
        super(host, port);
    }

    public GMSimpleSSLSocket(String host, int port, InetAddress localAddress, int localPort) throws IOException
    {
        super(host, port, localAddress, localPort);
    }

    public GMSimpleSSLSocket(InetAddress host, int port, InetAddress localAddress, int localPort) throws IOException
    {
        super(host, port, localAddress, localPort);
    }

    /**
     * set socket use client mode
     *
     * @param crypto crypto
     * @return GMSimpleSSLSocket
     */
    public GMSimpleSSLSocket useClientMode(TlsCrypto crypto)
    {
        this.useClientMode = true;
        this.crypto = crypto;
        this.certList = null;
        this.signKey = null;
        this.encKey = null;
        return this;
    }

    /**
     * set socket use server mode
     *
     * @param crypto   crypto
     * @param certList sign cert and encrypt cert
     * @param signKey  sign keypair
     * @param encKey   enc keypair
     * @return GMSimpleSSLSocket
     */
    public GMSimpleSSLSocket useServerMode(TlsCrypto crypto, Certificate certList, AsymmetricKeyParameter signKey, AsymmetricKeyParameter encKey)
    {
        this.useClientMode = false;
        this.crypto = crypto;
        this.certList = certList;
        this.signKey = signKey;
        this.encKey = encKey;
        return this;
    }


    @Override
    public String[] getSupportedCipherSuites()
    {
        return SUPPORT_CRYPTO_SUITES;
    }

    @Override
    public String[] getEnabledCipherSuites()
    {
        return SUPPORT_CRYPTO_SUITES;
    }

    @Override
    public void setEnabledCipherSuites(String[] strings)
    {

    }

    @Override
    public String[] getSupportedProtocols()
    {
        return SUPPORT_PROTOCOL_VERSIONS;
    }

    @Override
    public String[] getEnabledProtocols()
    {
        return SUPPORT_PROTOCOL_VERSIONS;
    }

    @Override
    public void setEnabledProtocols(String[] strings)
    {

    }

    @Override
    public void connect(SocketAddress endpoint) throws IOException
    {
        super.connect(endpoint);
    }

    @Override
    public SSLSession getSession()
    {
        // prevent apache HttpClient get session null throw error
        return session;
    }

    @Override
    public void addHandshakeCompletedListener(HandshakeCompletedListener handshakeCompletedListener)
    {

    }

    @Override
    public void removeHandshakeCompletedListener(HandshakeCompletedListener handshakeCompletedListener)
    {

    }

    @Override
    public void startHandshake() throws IOException
    {
        InputStream input = super.getInputStream();
        OutputStream output = super.getOutputStream();

        makeHandshake(input, output);
    }

    protected void makeHandshake(InputStream input, OutputStream output) throws IOException
    {
        if(session == null)
        {
            session = new GMSession(this);
        }
        if(this.useClientMode)
        {
            GmSimpleTlsClientProtocol clientProtocol = new GmSimpleTlsClientProtocol(input, output);
            this.protocol = clientProtocol;
            session.renew(clientProtocol);
            GMSimpleSSLClient client = new GMSimpleSSLClient(crypto);

            clientProtocol.connect(client);
        }
        else
        {
            GMSimpleSSLServer server = new GMSimpleSSLServer(crypto, certList, signKey, encKey);
            GmSimpleTlsServerProtocol serverProtocol = new GmSimpleTlsServerProtocol(input, output);
            session.renew(serverProtocol);
            this.protocol = serverProtocol;
            serverProtocol.accept(server);
        }

    }

    synchronized void handshakeIfNecessary() throws IOException
    {

        if (protocol == null || protocol.isHandshaking())
        {
            startHandshake();
        }
    }


    @Override
    public InputStream getInputStream() throws IOException
    {
        handshakeIfNecessary();
        return this.protocol.getInputStream();
    }

    @Override
    public OutputStream getOutputStream() throws IOException
    {
        handshakeIfNecessary();
        return this.protocol.getOutputStream();
    }

    @Override
    public void setUseClientMode(boolean b)
    {
        this.useClientMode = b;
    }

    @Override
    public boolean getUseClientMode()
    {
        return useClientMode;
    }

    @Override
    public void setNeedClientAuth(boolean b)
    {
    }

    @Override
    public boolean getNeedClientAuth()
    {
        return false;
    }

    @Override
    public void setWantClientAuth(boolean b)
    {

    }

    @Override
    public boolean getWantClientAuth()
    {
        return false;
    }

    @Override
    public void setEnableSessionCreation(boolean b)
    {

    }

    @Override
    public boolean getEnableSessionCreation()
    {
        return false;
    }

    @Override
    public synchronized void close() throws IOException
    {
        if(protocol != null)
        {
            protocol.close();
        }
    }



    @Override
    protected void finalize() throws Throwable
    {
        try
        {
            close();
        } catch (IOException e)
        {
            // Ignore
        } finally
        {
            super.finalize();
        }
    }
}
