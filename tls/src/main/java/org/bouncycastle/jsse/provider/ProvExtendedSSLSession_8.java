package org.bouncycastle.jsse.provider;

import java.util.Collections;
import java.util.List;

import javax.net.ssl.SNIServerName;

import org.bouncycastle.jsse.BCSNIServerName;

class ProvExtendedSSLSession_8
    extends ProvExtendedSSLSession_7
{
    ProvExtendedSSLSession_8(ProvSSLSession sslSession)
    {
        super(sslSession);
    }

    public List<SNIServerName> getRequestedServerNames()
    {
        List<BCSNIServerName> serverNames = sslSession.getRequestedServerNames();
        if (serverNames == null)
        {
            return Collections.emptyList();
        }
        return (List<SNIServerName>)JsseUtils_8.exportSNIServerNames(serverNames);
    }
}
