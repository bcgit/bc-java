package org.bouncycastle.jsse.provider;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.List;
import java.util.Locale;
import java.util.StringTokenizer;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.jsse.BCSNIHostName;
import org.bouncycastle.util.IPAddress;

class HostnameUtil
{
    static void checkHostname(String hostname, X509Certificate certificate, boolean allWildcards) throws CertificateException
    {
        if (null == hostname)
        {
            throw new CertificateException("No hostname specified for HTTPS endpoint ID check");
        }

        if (IPAddress.isValid(hostname))
        {
            Collection<List<?>> subjectAltNames = certificate.getSubjectAlternativeNames();
            if (null != subjectAltNames)
            {
                for (List<?> subjectAltName : subjectAltNames)
                {
                    int type = ((Integer)subjectAltName.get(0)).intValue();
                    if (GeneralName.iPAddress != type)
                    {
                        continue;
                    }

                    String ipAddress = (String)subjectAltName.get(1);
                    if (hostname.equalsIgnoreCase(ipAddress))
                    {
                        return;
                    }

                    try
                    {
                        if (InetAddress.getByName(hostname).equals(InetAddress.getByName(ipAddress)))
                        {
                            return;
                        }
                    }
                    catch (UnknownHostException e)
                    {
                        // Ignore
                    }
                    catch (SecurityException e)
                    {
                        // Ignore
                    }
                }
            }
            throw new CertificateException("No subject alternative name found matching IP address " + hostname);
        }
        else if (isValidDomainName(hostname))
        {
            Collection<List<?>> subjectAltNames = certificate.getSubjectAlternativeNames();
            if (null != subjectAltNames)
            {
                boolean foundAnyDNSNames = false;
                for (List<?> subjectAltName : subjectAltNames)
                {
                    int type = ((Integer)subjectAltName.get(0)).intValue();
                    if (GeneralName.dNSName != type)
                    {
                        continue;
                    }

                    foundAnyDNSNames = true;

                    String dnsName = (String)subjectAltName.get(1);
                    if (matchesDNSName(hostname, dnsName, allWildcards))
                    {
                        return;
                    }
                }

                // NOTE: If any DNS names were found, don't check the subject
                if (foundAnyDNSNames)
                {
                    throw new CertificateException("No subject alternative name found matching domain name " + hostname);
                }
            }

            ASN1Primitive commonName = findMostSpecificCN(certificate.getSubjectX500Principal());
            if (commonName instanceof ASN1String
                && matchesDNSName(hostname, ((ASN1String)commonName).getString(), allWildcards))
            {
                return;
            }

            throw new CertificateException("No name found matching " + hostname);
        }
        else
        {
            throw new CertificateException("Invalid hostname specified for HTTPS endpoint ID check");
        }
    }

    private static ASN1Primitive findMostSpecificCN(X500Principal principal)
    {
        if (null != principal)
        {
            RDN[] rdns = X500Name.getInstance(principal.getEncoded()).getRDNs();
            for (int i = rdns.length - 1; i >= 0; --i)
            {
                AttributeTypeAndValue[] typesAndValues = rdns[i].getTypesAndValues();
                for (int j = 0; j < typesAndValues.length; ++j)
                {
                    AttributeTypeAndValue typeAndValue = typesAndValues[j];
                    if (BCStyle.CN.equals(typeAndValue.getType()))
                    {
                        return typeAndValue.getValue().toASN1Primitive();
                    }
                }
            }
        }
        return null;
    }

    private static String getLabel(String s, int begin)
    {
        int end = s.indexOf('.', begin);
        if (end < 0)
        {
            end = s.length();
        }
        return s.substring(begin, end);
    }

    private static boolean isValidDomainName(String name)
    {
        try
        {
            new BCSNIHostName(name);
            return true;
        }
        catch (RuntimeException e)
        {
            return false;
        }
    }

    private static boolean labelMatchesPattern(String label, String pattern)
    {
        int wildcardPos = pattern.indexOf('*');
        if (wildcardPos < 0)
        {
            return label.equals(pattern);
        }

        int labelPos = 0, patternPos = 0;
        do
        {
            String segment = pattern.substring(patternPos, wildcardPos);

            int matchPos = label.indexOf(segment, labelPos);
            if (matchPos < 0 || (patternPos == 0 && matchPos > 0))
            {
                return false;
            }

            labelPos = matchPos + segment.length();
            patternPos = wildcardPos + 1;
        }
        while ((wildcardPos = pattern.indexOf('*', patternPos)) >= 0);

        String labelRest = label.substring(labelPos);
        String patternRest = pattern.substring(patternPos);

        return labelRest.endsWith(patternRest);
    }

    private static boolean matchesDNSName(String hostname, String dnsName, boolean allWildcards)
    {
        try
        {
            // TODO[jsse] 'hostname' conversion per call is redundant (and with isValidDomainName)
            hostname = IDNUtil.toUnicode(IDNUtil.toASCII(hostname, 0), 0);
            dnsName = IDNUtil.toUnicode(IDNUtil.toASCII(dnsName, 0), 0);
        }
        catch (RuntimeException e)
        {
            return false;
        }

        if (!validateWildcards(dnsName))
        {
            return false;
        }

        if (!isValidDomainName(dnsName.replace('*', 'z')))
        {
            return false;
        }

        hostname = hostname.toLowerCase(Locale.ENGLISH);
        dnsName = dnsName.toLowerCase(Locale.ENGLISH);

        return allWildcards
            ?  matchesWildcardsAllLabels(hostname, dnsName)
            :  matchesWildcardsFirstLabel(hostname, dnsName);
    }

    private static boolean matchesWildcardsAllLabels(String hostname, String dnsName)
    {
        StringTokenizer st1 = new StringTokenizer(hostname, ".");
        StringTokenizer st2 = new StringTokenizer(dnsName, ".");

        if (st1.countTokens() != st2.countTokens())
        {
            return false;
        }

        while (st1.hasMoreTokens())
        {
            String label = st1.nextToken();
            String pattern = st2.nextToken();

            if (!labelMatchesPattern(label, pattern))
            {
                return false;
            }
        }

        return true;
    }

    private static boolean matchesWildcardsFirstLabel(String hostname, String dnsName)
    {
        String hostnameLabel = getLabel(hostname, 0);
        String dnsNameLabel = getLabel(dnsName, 0);

        if (!labelMatchesPattern(hostnameLabel, dnsNameLabel))
        {
            return false;
        }

        String hostnameRest = hostname.substring(hostnameLabel.length()); 
        String dnsNameRest = dnsName.substring(dnsNameLabel.length());

        return hostnameRest.equals(dnsNameRest);
    }

    private static boolean validateWildcards(String dnsName)
    {
        int wildCardIndex = dnsName.lastIndexOf('*');
        if (wildCardIndex >= 0)
        {
            // TODO[jsse] Are these checks redundant?
            if (dnsName.equals("*") || dnsName.equals("*."))
            {
                return false;
            }

            // There must be at least one dot after the last wildcard
            int dotIndex = dnsName.indexOf('.', wildCardIndex + 1);
            if (dotIndex < 0)
            {
                return false;
            }

            /*
             * TODO[jsse] Wildcards not allowed in the label immediately before an ICANN public
             * suffix when certificate 'chainsToPublicCA' (a SunJSSE code term - exact meaning?).
             */
//            if (chainsToPublicCA)
//            {
//                String suffix = dnsName.substring(dotIndex).toLowerCase(Locale.ENGLISH);
//
//                // TODO[jsse] Implement (case-insensitive)
//                if (isPublicSuffix(suffix))
//                {
//                    return false;
//                }
//            }
        }

        return true;
    }
}
