package org.bouncycastle.jsse.provider;

import java.util.List;
import java.util.function.BiFunction;

import javax.net.ssl.SSLEngine;

class ProvSSLEngine_8
    extends ProvSSLEngine
{
    protected ProvSSLEngine_8(ContextData contextData)
    {
        super(contextData);
    }

    protected ProvSSLEngine_8(ContextData contextData, String host, int port)
    {
        super(contextData, host, port);
    }

    // An SSLEngine method from JDK 9 (and then 8u251)
    public synchronized void setHandshakeApplicationProtocolSelector(BiFunction<SSLEngine, List<String>, String> selector)
    {
        sslParameters.setEngineAPSelector(JsseUtils_8.importAPSelector(selector));
    }

    // An SSLEngine method from JDK 9 (and then 8u251)
    public synchronized BiFunction<SSLEngine, List<String>, String> getHandshakeApplicationProtocolSelector()
    {
        return JsseUtils_8.exportAPSelector(sslParameters.getEngineAPSelector());
    }
}
