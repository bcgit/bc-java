package org.bouncycastle.jsse.provider;

import javax.net.ssl.SNIHostName;

import org.bouncycastle.jsse.BCSNIServerName;
import org.bouncycastle.tls.NameType;

abstract class JsseUtilsv18
    extends JsseUtils
{
    static Object exportSNIServerName(BCSNIServerName serverName)
    {
        if (serverName == null || serverName.getType() != NameType.host_name)
        {
            return null;
        }

        return new SNIHostName(serverName.getEncoded());
    }
}
