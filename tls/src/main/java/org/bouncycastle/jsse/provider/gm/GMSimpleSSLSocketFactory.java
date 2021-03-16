package org.bouncycastle.jsse.provider.gm;

import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.jcajce.provider.asymmetric.GM;
import org.bouncycastle.tls.Certificate;
import org.bouncycastle.tls.crypto.TlsCrypto;
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto;

import javax.net.ssl.SSLSocketFactory;
import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.SecureRandom;

/**
 * Simple GMSSL Socket Factory
 *
 * @author Cliven
 * @since 2021-03-16 13:15:00
 */
public class GMSimpleSSLSocketFactory extends SSLSocketFactory
{

    private TlsCrypto crypto;
    private Certificate certList;
    private AsymmetricKeyParameter signKey, encKey;
    private Boolean clientMode = true;


    /**
     * Create Client side socket factory Instance
     */
    public GMSimpleSSLSocketFactory()
    {
        this.crypto = new BcTlsCrypto(new SecureRandom());
    }

    /**
     * Create server side socket factory Instance
     *
     * @param certList sign cert and encrypt cert
     * @param signKey sign key
     * @param encKey  enc key
     */
    public GMSimpleSSLSocketFactory(Certificate certList, AsymmetricKeyParameter signKey, AsymmetricKeyParameter encKey)
    {
        this();
        this.certList = certList;
        this.signKey = signKey;
        this.encKey = encKey;
        clientMode = false;
    }

    /**
     * Create Client side socket factory Instance
     * @return factory Instance
     */
    public static GMSimpleSSLSocketFactory ClientFactory()
    {
        return new GMSimpleSSLSocketFactory();
    }

    /**
     * Create server side socket factory Instance
     *
     * @param certList sign cert and encrypt cert
     * @param signKey sign key
     * @param encKey  enc key
     */
    public static GMSimpleSSLSocketFactory ServerFactory(Certificate certList, AsymmetricKeyParameter signKey,
                                                         AsymmetricKeyParameter encKey)
    {
        return new GMSimpleSSLSocketFactory(certList, signKey,encKey);
    }

    @Override
    public String[] getDefaultCipherSuites()
    {
        return GMSimpleSSLSocket.SUPPORT_CRYPTO_SUITES;
    }

    @Override
    public String[] getSupportedCipherSuites()
    {
        return GMSimpleSSLSocket.SUPPORT_CRYPTO_SUITES;
    }

    private GMSimpleSSLSocket ret(GMSimpleSSLSocket socket)
    {
        if(clientMode)
        {
            return socket.useClientMode(crypto);
        }
        else
        {
            return socket.useServerMode(crypto, certList, signKey, encKey);
        }
    }

    @Override
    public Socket createSocket(Socket socket, String host, int port, boolean autoClose) throws IOException
    {
        final GMSimpleSSLSocketWrap wrap = new GMSimpleSSLSocketWrap(socket, autoClose);
        return ret(wrap);
    }

    @Override
    public Socket createSocket(String host, int port) throws IOException, UnknownHostException
    {
        final GMSimpleSSLSocket socket = new GMSimpleSSLSocket(host, port);
        return ret(socket);
    }

    @Override
    public Socket createSocket(String host, int port, InetAddress inetAddress, int localPort) throws IOException, UnknownHostException
    {
        final GMSimpleSSLSocket socket = new GMSimpleSSLSocket(host, port, inetAddress, localPort);
        return ret(socket);
    }

    @Override
    public Socket createSocket(InetAddress inetAddress, int port) throws IOException
    {
        final GMSimpleSSLSocket socket = new GMSimpleSSLSocket(inetAddress, port);
        return ret(socket);
    }

    @Override
    public Socket createSocket(InetAddress inetAddress, int port, InetAddress localAddress, int localPort) throws IOException
    {
        final GMSimpleSSLSocket socket = new GMSimpleSSLSocket(inetAddress, port, localAddress, localPort);
        return ret(socket);
    }
}
