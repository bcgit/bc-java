package org.bouncycastle.cert;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AttCertIssuer;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.V2Form;
import org.bouncycastle.util.Selector;

/**
 * Carrying class for an attribute certificate issuer.
 */
public class AttributeCertificateIssuer
    implements Selector
{
    final ASN1Encodable form;

    /**
     * Set the issuer directly with the ASN.1 structure.
     *
     * @param issuer The issuer
     */
    public AttributeCertificateIssuer(AttCertIssuer issuer)
    {
        form = issuer.getIssuer();
    }

    public AttributeCertificateIssuer(X500Name principal)
    {
        form = new V2Form(new GeneralNames(new GeneralName(principal)));
    }

    public X500Name[] getNames()
    {
        GeneralNames name;

        if (form instanceof V2Form)
        {
            name = ((V2Form)form).getIssuerName();
        }
        else
        {
            name = (GeneralNames)form;
        }

        GeneralName[] names = name.getNames();

        return CertUtils.getPrincipals(names);
    }

    public Object clone()
    {
        return new AttributeCertificateIssuer(AttCertIssuer.getInstance(form));
    }

    public boolean equals(Object obj)
    {
        if (obj == this)
        {
            return true;
        }

        if (!(obj instanceof AttributeCertificateIssuer))
        {
            return false;
        }

        AttributeCertificateIssuer other = (AttributeCertificateIssuer)obj;

        return this.form.equals(other.form);
    }

    public int hashCode()
    {
        return this.form.hashCode();
    }

    public boolean match(Object obj)
    {
        if (!(obj instanceof X509CertificateHolder))
        {
            return false;
        }

        X509CertificateHolder x509Cert = (X509CertificateHolder)obj;
        GeneralNames name;
        if (form instanceof V2Form)
        {
            V2Form issuer = (V2Form)form;
            if (issuer.getBaseCertificateID() != null)
            {
                return issuer.getBaseCertificateID().getSerial().hasValue(x509Cert.getSerialNumber())
                    && CertUtils.matchesDN(x509Cert.getIssuer(), issuer.getBaseCertificateID().getIssuer());
            }

             name = issuer.getIssuerName();
        }
        else
        {
             name = (GeneralNames)form;
        }
        return CertUtils.matchesDN(x509Cert.getSubject(), name);
    }
}
