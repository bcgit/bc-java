package org.bouncycastle.jsse.provider;

import javax.net.ssl.SNIHostName;

import org.bouncycastle.jsse.BCSNIServerName;
import org.bouncycastle.tls.NameType;

abstract class JsseUtils_8
    extends JsseUtils
{
    static SNIHostName exportSNIServerName(BCSNIServerName serverName)
    {
        if (serverName == null || serverName.getType() != NameType.host_name)
        {
            return null;
        }

        return new SNIHostName(serverName.getEncoded());
    }
}
