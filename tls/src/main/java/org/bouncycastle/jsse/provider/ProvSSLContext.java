package org.bouncycastle.jsse.provider;

import java.security.KeyManagementException;
import java.security.SecureRandom;

import javax.net.ssl.*;
import javax.net.ssl.KeyManager;

class ProvSSLContext
    extends SSLContextSpi
{
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
