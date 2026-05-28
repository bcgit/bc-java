package org.bouncycastle.est.jcajce;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.net.ssl.SSLSession;
import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.est.ESTException;
import org.bouncycastle.util.IPAddress;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;


/**
 * A typical hostname authorizer for verifying a hostname against the available certificates.
 */
public class JsseDefaultHostnameAuthorizer
    implements JsseHostnameAuthorizer
{
    private static Logger LOG = Logger.getLogger(JsseDefaultHostnameAuthorizer.class.getName());

    private final Set<String> knownSuffixes;

    /**
     * Base constructor.
     * <p>
     * The authorizer attempts to perform matching (including the use of the wildcard) in accordance with RFC 9525 (formerly RFC 6125).
     * </p>
     * <p>
     * Known suffixes is a list of public domain suffixes that can't be used as wild cards for
     * example *.com, or c*c.com, as a dns wildcard could match every/most .com domains if a registrar were issue it.
     * If *.com is in the known suffixes list will not be allowed to match.
     * </p>
     *
     * @param knownSuffixes a set of suffixes that cannot be wild-carded, e.g. { ".com", ".net", ".org" }
     */
    public JsseDefaultHostnameAuthorizer(Set<String> knownSuffixes)
    {
        this.knownSuffixes = knownSuffixes;
    }

    public boolean verified(String name, SSLSession context)
        throws IOException
    {

        try
        {
            CertificateFactory fac = CertificateFactory.getInstance("X509");
            X509Certificate cert = (
                java.security.cert.X509Certificate)fac.generateCertificate(
                new ByteArrayInputStream((context.getPeerCertificates()[0]).getEncoded()));

            return verify(name, cert);
        }
        catch (Exception ex)
        {
            if (ex instanceof ESTException)
            {
                throw (ESTException)ex;
            }
            throw new ESTException(ex.getMessage(), ex);
        }
    }

    public boolean verify(String name, X509Certificate cert)
        throws IOException
    {
        if (name == null)
        {
            throw new NullPointerException("'name' cannot be null");
        }

        boolean foundAnyDNSNames = false;

        boolean nameIsIPv4 = IPAddress.isValidIPv4(name);
        boolean nameIsIPv6 = !nameIsIPv4 && IPAddress.isValidIPv6(name);
        boolean nameIsIPAddress = nameIsIPv4 || nameIsIPv6;

        //
        // Test against san.
        //
        try
        {
            Collection n = cert.getSubjectAlternativeNames();
            if (n != null)
            {
                InetAddress nameInetAddress = null;

                for (Iterator it = n.iterator(); it.hasNext();)
                {
                    List l = (List)it.next();
                    int type = ((Integer)l.get(0)).intValue();
                    switch (type)
                    {
                    case GeneralName.dNSName:
                    {
                        if (!nameIsIPAddress &&
                            isValidNameMatch(name, (String)l.get(1), knownSuffixes))
                        {
                            return true;
                        }
                        foundAnyDNSNames = true;
                        break;
                    }
                    case GeneralName.iPAddress:
                    {
                        if (nameIsIPAddress)
                        {
                            String ipAddress = (String)l.get(1);

                            if (name.equalsIgnoreCase(ipAddress))
                            {
                                return true;
                            }

                            // In case of IPv6 addresses, convert to InetAddress to handle abbreviated forms correctly
                            if (nameIsIPv6 && IPAddress.isValidIPv6(ipAddress))
                            {
                                try
                                {
                                    if (nameInetAddress == null)
                                    {
                                        nameInetAddress = InetAddress.getByName(name);
                                    }
                                    if (nameInetAddress.equals(InetAddress.getByName(ipAddress)))
                                    {
                                        return true;
                                    }
                                }
                                catch (UnknownHostException e)
                                {
                                    // Ignore
                                }
                            }
                        }
                        break;
                    }
                    default:
                    {
                        // ignore, maybe log
                        if (LOG.isLoggable(Level.INFO))
                        {
                            String value;
                            if (l.get(1) instanceof byte[])
                            {
                                // -DM Hex.toHexString
                                value = Hex.toHexString((byte[])l.get(1));
                            }
                            else
                            {
                                value = l.get(1).toString();
                            }

                            LOG.log(Level.INFO, "ignoring type " + type + " value = " + value);
                        }
                    }
                    }
                }
            }
        }
        catch (Exception ex)
        {
            throw new ESTException(ex.getMessage(), ex);
        }

        // If we found any DNS names in the subject alternative names, we must not attempt to match against the CN.
        if (nameIsIPAddress || foundAnyDNSNames)
        {
            return false;
        }

        X500Principal subject = cert.getSubjectX500Principal();

        // can't match - would need to check subjectAltName
        if (subject == null)
        {
            return false;
        }

        // Common Name match only.
        RDN[] rdns = X500Name.getInstance(subject.getEncoded()).getRDNs();
        for (int i = rdns.length - 1; i >= 0; --i)
        {
            AttributeTypeAndValue[] typesAndValues = rdns[i].getTypesAndValues();
            for (int j = 0; j != typesAndValues.length; j++)
            {
                AttributeTypeAndValue typeAndValue = typesAndValues[j];
                if (BCStyle.CN.equals(typeAndValue.getType()))
                {
                    ASN1Primitive commonName = typeAndValue.getValue().toASN1Primitive();
                    return commonName instanceof ASN1String
                        && isValidNameMatch(name, ((ASN1String)commonName).getString(), knownSuffixes);
                }
            }
        }
        return false;
    }


    public static boolean isValidNameMatch(String name, String dnsName, Set<String> suffixes)
        throws IOException
    {

        //
        // Wild card matching.
        //
        if (dnsName.contains("*"))
        {
            // RFC 9525 sec. 6.3 (obsoletes RFC 6125): a wildcard match is only valid when there
            // is exactly one '*' and it is the complete content of the left-most label (i.e.
            // dnsName has the form "*.<rest>"), and it matches exactly one label. Partial
            // wildcards ("x*", "*x", "f*o") and wildcards in any other label are rejected; this
            // also stops a wildcard from matching across an internationalized A-label such as
            // "xn--..." (the name-confusion case in github #1495).
            int wildIndex = dnsName.indexOf('*');

            if (wildIndex != dnsName.lastIndexOf('*')    // more than one '*'
                || wildIndex != 0                        // '*' is not at the start of the name
                || dnsName.length() < 2
                || dnsName.charAt(1) != '.'              // '*' is not the whole left-most label
                || dnsName.contains(".."))
            {
                return false;
            }

            int dnsDotIndex = dnsName.indexOf('.', wildIndex);
            if (suffixes != null && suffixes.contains(Strings.toLowerCase(dnsName.substring(dnsDotIndex))))
            {
                throw new IOException("Wildcard `" + dnsName + "` matches known public suffix.");
            }

            String end = Strings.toLowerCase(dnsName.substring(1));   // ".<rest>"
            String loweredName = Strings.toLowerCase(name);

            if (!loweredName.endsWith(end))
            {
                return false;
            }

            // the '*' must stand in for exactly one non-empty label (no embedded dot, not empty).
            String matched = loweredName.substring(0, loweredName.length() - end.length());
            return matched.length() > 0 && matched.indexOf('.') < 0;
        }

        //
        // No wild card full equality but ignore case.
        //
        return name.equalsIgnoreCase(dnsName);
    }
}
