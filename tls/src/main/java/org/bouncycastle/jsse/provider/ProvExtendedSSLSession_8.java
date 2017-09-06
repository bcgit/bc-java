package org.bouncycastle.jsse.provider;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import javax.net.ssl.SNIHostName;
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
        if (serverNames != null)
        {
            ArrayList<SNIServerName> result = new ArrayList<SNIServerName>(serverNames.size());
            for (BCSNIServerName serverName : serverNames)
            {
                SNIHostName exported = JsseUtils_8.exportSNIServerName(serverName);
                if (exported != null)
                {
                    result.add(exported);
                }
            }
            if (!result.isEmpty())
            {
                return Collections.unmodifiableList(result);
            }
        }
        return Collections.emptyList();
    }
}
