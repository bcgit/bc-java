package org.bouncycastle.jsse.provider;

import java.util.Collections;
import java.util.List;

import javax.net.ssl.SNIServerName;

import org.bouncycastle.jsse.BCExtendedSSLSession;
import org.bouncycastle.jsse.BCSNIServerName;

class ExportSSLSession_8
    extends ExportSSLSession_7
{
    ExportSSLSession_8(BCExtendedSSLSession sslSession)
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
