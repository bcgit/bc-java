package org.bouncycastle.est.jcajce;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.net.ssl.SSLSession;

import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.est.ESTException;
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
     * The authorizer attempts to perform matching (including the use of the wildcard) in accordance with RFC 6125.
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
        //
        // Test against san.
        //
        try
        {
            Collection n = cert.getSubjectAlternativeNames();
            if (n != null)
            {
                for (Iterator it = n.iterator(); it.hasNext();)
                {
                    List l = (List)it.next();
                    int type = ((Number)l.get(0)).intValue();
                    switch (type)
                    {
                    case 2:
                        if (isValidNameMatch(name, l.get(1).toString(), knownSuffixes))
                        {
                            return true;
                        }
                        break;
                    case 7:
                        if (InetAddress.getByName(name).equals(InetAddress.getByName(l.get(1).toString())))
                        {
                            return true;
                        }
                        break;
                    default:
                        // ignore, maybe log
                        if (LOG.isLoggable(Level.INFO))
                        {
                            String value;
                            if (l.get(1) instanceof byte[])
                            {
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

                //
                // As we had subject alternative names, we must not attempt to match against the CN.
                //

                return false;
            }
        }
        catch (Exception ex)
        {
            throw new ESTException(ex.getMessage(), ex);
        }

        // can't match - would need to check subjectAltName
        if (cert.getSubjectX500Principal() == null)
        {
            return false;
        }

        // Common Name match only.
        RDN[] rdNs = X500Name.getInstance(cert.getSubjectX500Principal().getEncoded()).getRDNs();
        for (int i = rdNs.length - 1; i >= 0; --i)
        {
            RDN rdn = rdNs[i];
            AttributeTypeAndValue[] typesAndValues = rdn.getTypesAndValues();
            for (int j = 0; j != typesAndValues.length; j++)
            {
                AttributeTypeAndValue atv = typesAndValues[j];
                if (atv.getType().equals(BCStyle.CN))
                {
                    return isValidNameMatch(name, atv.getValue().toString(), knownSuffixes);
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
            // Only one astrix 
            int wildIndex = dnsName.indexOf('*');
            if (wildIndex == dnsName.lastIndexOf("*"))
            {
                if (dnsName.contains("..") || dnsName.charAt(dnsName.length() - 1) == '*')
                {
                    return false;
                }

                int dnsDotIndex = dnsName.indexOf('.', wildIndex);

                if (suffixes != null && suffixes.contains(Strings.toLowerCase(dnsName.substring(dnsDotIndex))))
                {
                    throw new IOException("Wildcard `" + dnsName + "` matches known public suffix.");
                }

                String end = Strings.toLowerCase(dnsName.substring(wildIndex + 1));
                String loweredName = Strings.toLowerCase(name);

                if (loweredName.equals(end))
                {
                    return false; // Must not match wild card exactly there must content to the left of the wildcard.
                }

                if (end.length() > loweredName.length())
                {
                    return false;
                }

                if (wildIndex > 0)
                {
                    if (loweredName.startsWith(dnsName.substring(0, wildIndex)) && loweredName.endsWith(end))
                    {
                        return loweredName.substring(wildIndex, loweredName.length() - end.length()).indexOf('.') < 0;
                    }
                    else
                    {
                        return false;
                    }
                }

                // Must be only one '*' and it must be at position 0.
                String prefix = loweredName.substring(0, loweredName.length() - end.length());
                if (prefix.indexOf('.') > 0)
                {
                    return false;
                }

                return loweredName.endsWith(end);
            }

            return false;
        }

        //
        // No wild card full equality but ignore case.
        //
        return name.equalsIgnoreCase(dnsName);
    }
}
