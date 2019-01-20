package org.bouncycastle.jsse.provider;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

import javax.net.ssl.SNIHostName;
import javax.net.ssl.SNIMatcher;
import javax.net.ssl.SNIServerName;
import javax.net.ssl.StandardConstants;

import org.bouncycastle.jsse.BCSNIHostName;
import org.bouncycastle.jsse.BCSNIMatcher;
import org.bouncycastle.jsse.BCSNIServerName;
import org.bouncycastle.jsse.BCStandardConstants;

abstract class JsseUtils_8
    extends JsseUtils_7
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

    static class UnknownServerName extends SNIServerName
    {
        UnknownServerName(int type, byte[] encoded)
        {
            super(type, encoded);
        }
    }

    static SNIMatcher exportSNIMatcher(BCSNIMatcher matcher)
    {
        if (null == matcher)
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
        if (null == matchers)
        {
            return null;
        }

        ArrayList<SNIMatcher> result = new ArrayList<SNIMatcher>(matchers.size());
        for (BCSNIMatcher matcher : matchers)
        {
            SNIMatcher exported = exportSNIMatcher(matcher);
            if (null != exported)
            {
                result.add(exported);
            }
        }

        if (result.isEmpty())
        {
            return Collections.<SNIMatcher>emptyList();
        }

        return Collections.unmodifiableList(result);
    }

    static SNIServerName exportSNIServerName(BCSNIServerName serverName)
    {
        if (null == serverName)
        {
            return null;
        }

        int type = serverName.getType();
        byte[] encoded = serverName.getEncoded();

        switch (type)
        {
        case BCStandardConstants.SNI_HOST_NAME:
            return new SNIHostName(encoded);
        default:
            return new UnknownServerName(type, encoded);
        }
    }

    /*
     * NOTE: Currently return type is Object to isolate callers from JDK8 type
     */
    static Object exportSNIServerNames(Collection<BCSNIServerName> serverNames)
    {
        if (null == serverNames)
        {
            return null;
        }

        ArrayList<SNIServerName> result = new ArrayList<SNIServerName>(serverNames.size());
        for (BCSNIServerName serverName : serverNames)
        {
            SNIServerName exported = exportSNIServerName(serverName);
            if (null != exported)
            {
                result.add(exported);
            }
        }

        if (result.isEmpty())
        {
            return Collections.<SNIServerName>emptyList();
        }

        return Collections.unmodifiableList(result);
    }

    static BCSNIMatcher importSNIMatcher(SNIMatcher matcher)
    {
        if (null == matcher)
        {
            return null;
        }

        if (matcher instanceof ExportSNIMatcher)
        {
            return ((ExportSNIMatcher)matcher).unwrap();
        }

        return new ImportSNIMatcher(matcher);
    }

    /*
     * NOTE: Currently argument is Object type to isolate callers from JDK8 type
     */
    static List<BCSNIMatcher> importSNIMatchers(Object getSNIMatchersResult)
    {
        if (null == getSNIMatchersResult)
        {
            return null;
        }

        @SuppressWarnings("unchecked")
        Collection<SNIMatcher> matchers = (Collection<SNIMatcher>)getSNIMatchersResult;

        ArrayList<BCSNIMatcher> result = new ArrayList<BCSNIMatcher>(matchers.size());
        for (SNIMatcher matcher : matchers)
        {
            BCSNIMatcher imported = importSNIMatcher(matcher);
            if (null != imported)
            {
                result.add(imported);
            }
        }

        if (result.isEmpty())
        {
            return Collections.<BCSNIMatcher>emptyList();
        }

        return Collections.unmodifiableList(result);
    }

    static BCSNIServerName importSNIServerName(SNIServerName serverName)
    {
        if (null == serverName)
        {
            return null;
        }

        int type = serverName.getType();
        byte[] encoded = serverName.getEncoded();

        switch (type)
        {
        case StandardConstants.SNI_HOST_NAME:
            return new BCSNIHostName(encoded);
        default:
            return new BCUnknownServerName(type, encoded);
        }
    }

    /*
     * NOTE: Currently argument is Object type to isolate callers from JDK8 type
     */
    static List<BCSNIServerName> importSNIServerNames(Object getServerNamesResult)
    {
        if (null == getServerNamesResult)
        {
            return null;
        }

        @SuppressWarnings("unchecked")
        Collection<SNIServerName> serverNames = (Collection<SNIServerName>)getServerNamesResult;

        ArrayList<BCSNIServerName> result = new ArrayList<BCSNIServerName>(serverNames.size());
        for (SNIServerName serverName : serverNames)
        {
            BCSNIServerName imported = importSNIServerName(serverName);
            if (null != imported)
            {
                result.add(imported);
            }
        }

        if (result.isEmpty())
        {
            return Collections.<BCSNIServerName>emptyList();
        }

        return Collections.unmodifiableList(result);
    }
}
