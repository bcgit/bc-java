package org.bouncycastle.jsse.provider;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import javax.net.ssl.SNIHostName;
import javax.net.ssl.SNIServerName;

import org.bouncycastle.jsse.BCSNIHostName;
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

    /*
     * NOTE: Currently return type is Object to isolate callers from JDK8 type
     */
    static Object exportSNIServerNames(List<BCSNIServerName> serverNames)
    {
        if (serverNames == null)
        {
            return null;
        }

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
        return Collections.<SNIServerName>emptyList();
    }

    static BCSNIHostName importSNIServerName(SNIServerName serverName)
    {
        if (serverName == null || serverName.getType() != NameType.host_name)
        {
            return null;
        }

        return new BCSNIHostName(serverName.getEncoded());
    }

    /*
     * NOTE: Currently argument is Object type to isolate callers from JDK8 type
     */
    static List<BCSNIServerName> importSNIServerNames(Object getServerNamesResult)
    {
        if (getServerNamesResult == null)
        {
            return null;
        }

        List<SNIServerName> serverNames = (List<SNIServerName>)getServerNamesResult;

        ArrayList<BCSNIServerName> result = new ArrayList<BCSNIServerName>(serverNames.size());
        for (SNIServerName serverName : serverNames)
        {
            BCSNIHostName imported = importSNIServerName(serverName);
            if (imported != null)
            {
                result.add(imported);
            }
        }
        if (!result.isEmpty())
        {
            return Collections.unmodifiableList(result);
        }
        return Collections.<BCSNIServerName>emptyList();
    }
}
