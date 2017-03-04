package org.bouncycastle.est.jcajce;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.List;

import javax.net.ssl.SSLSession;

import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.est.ESTException;
import org.bouncycastle.util.Strings;


public class JsseDefaultHostnameVerifier
    implements JsseHostnameAuthorizer
{
    public boolean verified(String name, SSLSession context)
        throws IOException
    {

        try
        {
            CertificateFactory fac = CertificateFactory.getInstance("X509");
            X509Certificate cert = (
                java.security.cert.X509Certificate)fac.generateCertificate(
                new ByteArrayInputStream(((javax.security.cert.X509Certificate)context.getPeerCertificateChain()[0]).getEncoded()));

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
                        if (testName(name, l.get(1).toString()))
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
                    return testName(name, rdn.getFirst().getValue().toString());
                }
            }
        }
        return false;
    }


    public boolean testName(String name, String dnsName)
    {

        if (dnsName.startsWith("*"))
        {
            if (dnsName.endsWith("."))
            {
                dnsName = dnsName.substring(0, dnsName.length() - 1);
            }

            return Strings.toLowerCase(name).endsWith(Strings.toLowerCase(dnsName.substring(1)));
        }

        return name.equalsIgnoreCase(dnsName);
    }
}
