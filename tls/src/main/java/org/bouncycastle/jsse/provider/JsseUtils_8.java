package org.bouncycastle.jsse.provider;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

import javax.net.ssl.SNIHostName;
import javax.net.ssl.SNIMatcher;
import javax.net.ssl.SNIServerName;

import org.bouncycastle.jsse.BCSNIHostName;
import org.bouncycastle.jsse.BCSNIMatcher;
import org.bouncycastle.jsse.BCSNIServerName;
import org.bouncycastle.jsse.BCStandardConstants;

abstract class JsseUtils_8
    extends JsseUtils
{
    static class ExportSNIMatcher extends SNIMatcher
    {
        private final BCSNIMatcher matcher;

        ExportSNIMatcher(BCSNIMatcher matcher)
        {
            super(matcher.getType());

            this.matcher = matcher;
        }

        @Override
        public boolean matches(SNIServerName serverName)
        {
            return matcher.matches(importSNIServerName(serverName));
        }

        BCSNIMatcher unwrap()
        {
            return matcher;
        }
    }

    static class ImportSNIMatcher extends BCSNIMatcher
    {
        private final SNIMatcher matcher;

        ImportSNIMatcher(SNIMatcher matcher)
        {
            super(matcher.getType());

            this.matcher = matcher;
        }

        @Override
        public boolean matches(BCSNIServerName serverName)
        {
            return matcher.matches(exportSNIServerName(serverName));
        }

        SNIMatcher unwrap()
        {
            return matcher;
        }
    }

    static SNIMatcher exportSNIMatcher(BCSNIMatcher matcher)
    {
        if (matcher == null)
        {
            return null;
        }

        if (matcher instanceof ImportSNIMatcher)
        {
            return ((ImportSNIMatcher)matcher).unwrap();
        }

        return new ExportSNIMatcher(matcher);
    }

    /*
     * NOTE: Currently return type is Object to isolate callers from JDK8 type
     */
    static Object exportSNIMatchers(Collection<BCSNIMatcher> matchers)
    {
        if (matchers == null)
        {
            return null;
        }

        ArrayList<SNIMatcher> result = new ArrayList<SNIMatcher>(matchers.size());
        for (BCSNIMatcher matcher : matchers)
        {
            SNIMatcher exported = exportSNIMatcher(matcher);
            if (exported != null)
            {
                result.add(exported);
            }
        }

        if (!result.isEmpty())
        {
            return Collections.unmodifiableList(result);
        }

        return Collections.<SNIMatcher>emptyList();
    }

    static SNIHostName exportSNIServerName(BCSNIServerName serverName)
    {
        if (serverName == null || serverName.getType() != BCStandardConstants.SNI_HOST_NAME)
        {
            return null;
        }

        return new SNIHostName(serverName.getEncoded());
    }

    /*
     * NOTE: Currently return type is Object to isolate callers from JDK8 type
     */
    static Object exportSNIServerNames(Collection<BCSNIServerName> serverNames)
    {
        if (serverNames == null)
        {
            return null;
        }

        ArrayList<SNIServerName> result = new ArrayList<SNIServerName>(serverNames.size());
        for (BCSNIServerName serverName : serverNames)
        {
            SNIHostName exported = exportSNIServerName(serverName);
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

    static BCSNIMatcher importSNIMatcher(SNIMatcher matcher)
    {
        if (matcher == null)
        {
            return null;
        }

        if (matcher instanceof ExportSNIMatcher)
        {
            return ((ExportSNIMatcher)matcher).unwrap();
        }

        return new ImportSNIMatcher(matcher);
    }

    static List<BCSNIMatcher> importSNIMatchers(Object getSNIMatchersResult)
    {
        if (getSNIMatchersResult == null)
        {
            return null;
        }

        Collection<SNIMatcher> matchers = (Collection<SNIMatcher>)getSNIMatchersResult;

        ArrayList<BCSNIMatcher> result = new ArrayList<BCSNIMatcher>(matchers.size());
        for (SNIMatcher matcher : matchers)
        {
            BCSNIMatcher imported = importSNIMatcher(matcher);
            if (imported != null)
            {
                result.add(imported);
            }
        }

        if (!result.isEmpty())
        {
            return Collections.unmodifiableList(result);
        }

        return Collections.<BCSNIMatcher>emptyList();
    }

    static BCSNIHostName importSNIServerName(SNIServerName serverName)
    {
        if (serverName == null || serverName.getType() != BCStandardConstants.SNI_HOST_NAME)
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

        Collection<SNIServerName> serverNames = (Collection<SNIServerName>)getServerNamesResult;

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
