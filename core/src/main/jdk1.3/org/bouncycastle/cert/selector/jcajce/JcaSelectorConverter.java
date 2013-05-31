package org.bouncycastle.cert.selector.jcajce;

import org.bouncycastle.jce.cert.X509CertSelector;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.selector.X509CertificateHolderSelector;

public class JcaSelectorConverter
{
    public JcaSelectorConverter()
    {

    }

    public X509CertificateHolderSelector getCertificateHolderSelector(X509CertSelector certSelector)
    {
try
{
        if (certSelector.getSubjectKeyIdentifier() != null)
        {
            return new X509CertificateHolderSelector(X500Name.getInstance(certSelector.getIssuerAsBytes()), certSelector.getSerialNumber(), ASN1OctetString.getInstance(certSelector.getSubjectKeyIdentifier()).getOctets());
        }
        else
        {
            return new X509CertificateHolderSelector(X500Name.getInstance(certSelector.getIssuerAsBytes()), certSelector.getSerialNumber());
        }
}
catch (Exception e)
{
throw new IllegalArgumentException("conversion failed: " + e.toString());
}
    }
}
