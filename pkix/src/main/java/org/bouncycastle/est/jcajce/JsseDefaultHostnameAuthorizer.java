package org.bouncycastle.est.jcajce;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.List;
import java.util.Set;

import javax.net.ssl.SSLSession;

import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.est.ESTException;
import org.bouncycastle.util.Strings;


/**
 * A typical hostname authorizer for verifying a hostname against the available certificates.
 */
public class JsseDefaultHostnameAuthorizer
    implements JsseHostnameAuthorizer
{

    private final Set<String> knownSuffixes;

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
            Collection<List<?>> n = cert.getSubjectAlternativeNames();
            if (n != null)
            {
                for (List l : n)
                {
                    switch (((Number)l.get(0)).intValue())
                    {
                    case 2:
                        if (testName(name, l.get(1).toString(), knownSuffixes ))
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
                        throw new RuntimeException("Unable to handle ");
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

        // Common Name match only.
        for (RDN rdn : X500Name.getInstance(cert.getSubjectX500Principal().getEncoded()).getRDNs())
        {
            for (AttributeTypeAndValue atv : rdn.getTypesAndValues())
            {
                if (atv.getType().equals(BCStyle.CN))
                {
                    return testName(name, rdn.getFirst().getValue().toString(), knownSuffixes);
                }
            }
        }
        return false;
    }


    public static boolean testName(String name, String dnsName, Set<String> suffixes)
        throws IOException
    {

        //
        // Wild card matching.
        //
        if (dnsName.contains("*"))
        {
            // Only one astrix and it must be at the start of the wildcard.
            if (dnsName.indexOf('*') == dnsName.lastIndexOf("*") && dnsName.indexOf('*') == 0)
            {

                if (dnsName.contains("..") || dnsName.equals("*"))
                {
                    return false;
                }

                if (suffixes != null && suffixes.contains(Strings.toLowerCase(dnsName)))
                {
                    throw new IOException("Wildcard `" + dnsName + "` is known public suffix.");
                }

                String end = Strings.toLowerCase(dnsName.substring(1));
                if (Strings.toLowerCase(name).equals(end))
                {
                    return false; // Must not match wild card exactly there must content to the left of the wildcard.
                }

                // Must be only one '*' and it must be at position 0.
                return Strings.toLowerCase(name).endsWith(end);
            }

            return false;
        }

        //
        // No wild card full equality but ignore case.
        //
        return name.equalsIgnoreCase(dnsName);
    }
}
