package org.bouncycastle.jsse.provider;

class ProvSSLEngineCreator
{
    static ProvSSLEngine create(ProvSSLContextSpi context, ContextData contextData)
    {
        return new ProvSSLEngine_9(context, contextData);
    }

    static ProvSSLEngine create(ProvSSLContextSpi context, ContextData contextData, String host, int port)
    {
        return new ProvSSLEngine_9(context, contextData, host, port);
    }
}
