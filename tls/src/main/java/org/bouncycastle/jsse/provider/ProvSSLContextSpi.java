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

class ProvSSLContextSpi
    extends SSLContextSpi
{
    ProvSSLContextSpi(TlsCrypto crypto)
    {
    }

    @Override
    protected SSLEngine engineCreateSSLEngine()
    {
        throw new UnsupportedOperationException();
    }

    @Override
    protected SSLEngine engineCreateSSLEngine(String host, int port)
    {
        throw new UnsupportedOperationException();
    }

    @Override
    protected SSLSessionContext engineGetClientSessionContext()
    {
        throw new UnsupportedOperationException();
    }

//  @Override
//  protected SSLParameters engineGetDefaultSSLParameters()
//  {
//      return super.engineGetDefaultSSLParameters();
//  }

    @Override
    protected SSLSessionContext engineGetServerSessionContext()
    {
        throw new UnsupportedOperationException();
    }

    @Override
    protected SSLServerSocketFactory engineGetServerSocketFactory()
    {
        throw new UnsupportedOperationException();
    }

    @Override
    protected SSLSocketFactory engineGetSocketFactory()
    {
        throw new UnsupportedOperationException();
    }

//  @Override
//  protected SSLParameters engineGetSupportedSSLParameters()
//  {
//      return super.engineGetSupportedSSLParameters();
//  }

    @Override
    protected void engineInit(KeyManager[] km, TrustManager[] tm, SecureRandom sr) throws KeyManagementException
    {
        throw new UnsupportedOperationException();
    }
}
