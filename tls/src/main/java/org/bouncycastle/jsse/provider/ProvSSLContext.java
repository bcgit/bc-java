package org.bouncycastle.jsse.provider;

import java.security.KeyManagementException;
import java.security.SecureRandom;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContextSpi;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSessionContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;

import org.bouncycastle.tls.TlsCrypto;

class ProvSSLContext
    extends SSLContextSpi
{
    public ProvSSLContext(TlsCrypto crypto)
    {

    }

    protected void engineInit(KeyManager[] keyManagers, TrustManager[] trustManagers, SecureRandom secureRandom)
        throws KeyManagementException
    {

    }

    protected SSLSocketFactory engineGetSocketFactory()
    {
        return null;
    }

    protected SSLServerSocketFactory engineGetServerSocketFactory()
    {
        return null;
    }

    protected SSLEngine engineCreateSSLEngine()
    {
        return null;
    }

    protected SSLEngine engineCreateSSLEngine(String host, int port)
    {
        return null;
    }

    protected SSLSessionContext engineGetServerSessionContext()
    {
        return null;
    }

    protected SSLSessionContext engineGetClientSessionContext()
    {
        return null;
    }
}
