package org.bouncycastle.jsse.provider;

import javax.net.ssl.SSLEngine;

import org.bouncycastle.jsse.BCSSLEngine;

abstract class ProvSSLEngine
    extends SSLEngine
    implements BCSSLEngine, ProvTlsManager
{
    protected ProvSSLEngine()
    {
        super();
    }

    protected ProvSSLEngine(String host, int port)
    {
        super(host, port);
    }

    static ProvSSLEngine create(ProvSSLContextSpi context, ContextData contextData)
    {
        return new ProvSSLEngine_5(context, contextData);
    }

    static ProvSSLEngine create(ProvSSLContextSpi context, ContextData contextData, String host, int port)
    {
        return new ProvSSLEngine_5(context, contextData, host, port);
    }
}
