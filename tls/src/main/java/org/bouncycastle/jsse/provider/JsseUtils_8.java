package org.bouncycastle.jsse.provider;

import java.security.cert.CertPathBuilder;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXCertPathChecker;
import java.security.cert.PKIXRevocationChecker;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;

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

    static void addStatusResponses(CertPathBuilder pkixBuilder, PKIXBuilderParameters pkixParameters,
        Map<X509Certificate, byte[]> statusResponseMap)
    {
        if (statusResponseMap.isEmpty())
        {
            return;
        }

        List<PKIXCertPathChecker> certPathCheckers = pkixParameters.getCertPathCheckers();
        PKIXRevocationChecker existingChecker = getFirstRevocationChecker(certPathCheckers);

        if (null != existingChecker)
        {
            // NOTE: Existing checker will be used irrespective of pkixParameters.isRevocationEnabled
            Map<X509Certificate, byte[]> ocspResponses = existingChecker.getOcspResponses();
            if (putAnyAbsent(ocspResponses, statusResponseMap) > 0)
            {
                existingChecker.setOcspResponses(ocspResponses);
                pkixParameters.setCertPathCheckers(certPathCheckers);
            }
        }
        else
        {
            if (pkixParameters.isRevocationEnabled())
            {
                PKIXRevocationChecker checker = (PKIXRevocationChecker)pkixBuilder.getRevocationChecker();
                checker.setOcspResponses(statusResponseMap);
                pkixParameters.addCertPathChecker(checker);
            }
        }
    }

    static List<SNIMatcher> exportSNIMatchers(Collection<BCSNIMatcher> matchers)
    {
        if (null == matchers || matchers.isEmpty())
        {
            return Collections.<SNIMatcher>emptyList();
        }

        ArrayList<SNIMatcher> result = new ArrayList<SNIMatcher>(matchers.size());
        for (BCSNIMatcher matcher : matchers)
        {
            result.add(exportSNIMatcher(matcher));
        }
        return Collections.unmodifiableList(result);
    }

    /*
     * NOTE: Return type is Object to isolate callers from JDK 8 type
     */
    static Object exportSNIMatchersDynamic(Collection<BCSNIMatcher> matchers)
    {
        return exportSNIMatchers(matchers);
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

    static List<SNIServerName> exportSNIServerNames(Collection<BCSNIServerName> serverNames)
    {
        if (null == serverNames || serverNames.isEmpty())
        {
            return Collections.<SNIServerName>emptyList();
        }

        ArrayList<SNIServerName> result = new ArrayList<SNIServerName>(serverNames.size());
        for (BCSNIServerName serverName : serverNames)
        {
            result.add(exportSNIServerName(serverName));
        }
        return Collections.unmodifiableList(result);
    }

    /*
     * NOTE: Return type is Object to isolate callers from JDK 8 type
     */
    static Object exportSNIServerNamesDynamic(Collection<BCSNIServerName> serverNames)
    {
        return exportSNIServerNames(serverNames);
    }

    static PKIXRevocationChecker getFirstRevocationChecker(List<PKIXCertPathChecker> certPathCheckers)
    {
        for (PKIXCertPathChecker certPathChecker : certPathCheckers)
        {
            if (certPathChecker instanceof PKIXRevocationChecker)
            {
                return (PKIXRevocationChecker)certPathChecker;
            }
        }
        return null;
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

    static List<BCSNIMatcher> importSNIMatchers(Collection<SNIMatcher> matchers)
    {
        if (null == matchers || matchers.isEmpty())
        {
            return Collections.emptyList();
        }

        ArrayList<BCSNIMatcher> result = new ArrayList<BCSNIMatcher>(matchers.size());
        for (SNIMatcher matcher : matchers)
        {
            result.add(importSNIMatcher(matcher));
        }
        return Collections.unmodifiableList(result);
    }

    /*
     * NOTE: Argument type is Object to isolate callers from JDK 8 type
     */
    @SuppressWarnings("unchecked")
    static List<BCSNIMatcher> importSNIMatchersDynamic(Object matchers)
    {
        return importSNIMatchers((Collection<SNIMatcher>)matchers);
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

    static List<BCSNIServerName> importSNIServerNames(Collection<SNIServerName> serverNames)
    {
        if (null == serverNames || serverNames.isEmpty())
        {
            return Collections.emptyList();
        }

        ArrayList<BCSNIServerName> result = new ArrayList<BCSNIServerName>(serverNames.size());
        for (SNIServerName serverName : serverNames)
        {
            result.add(importSNIServerName(serverName));
        }
        return Collections.unmodifiableList(result);
    }

    /*
     * NOTE: Argument type is Object to isolate callers from JDK 8 type
     */
    @SuppressWarnings("unchecked")
    static List<BCSNIServerName> importSNIServerNamesDynamic(Object serverNames)
    {
        return importSNIServerNames((Collection<SNIServerName>)serverNames);
    }

    static <K, V> int putAnyAbsent(Map<K, V> to, Map<K, V> from)
    {
        int count = 0;
        for (Map.Entry<K, V> entry : from.entrySet())
        {
            if (null == to.putIfAbsent(entry.getKey(), entry.getValue()))
            {
                ++count;
            }
        }
        return count;
    }
}
