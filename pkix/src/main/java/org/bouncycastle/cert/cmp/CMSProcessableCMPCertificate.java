package org.bouncycastle.cert.cmp;

import java.io.IOException;
import java.io.OutputStream;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cmp.CMPCertificate;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSTypedData;

/**
 * Carrier class for a CMPCertificate over CMS.
 */
public class CMSProcessableCMPCertificate
    implements CMSTypedData
{
    private final CMPCertificate cmpCert;

    public CMSProcessableCMPCertificate(X509CertificateHolder certificateHolder)
    {
        this(new CMPCertificate(certificateHolder.toASN1Structure()));
    }

    public CMSProcessableCMPCertificate(CMPCertificate cmpCertificate)
    {
        this.cmpCert = cmpCertificate;
    }

    @Override
    public void write(OutputStream out)
        throws IOException, CMSException
    {
        out.write(cmpCert.getEncoded());
    }

    @Override
    public Object getContent()
    {
        return cmpCert;
    }

    @Override
    public ASN1ObjectIdentifier getContentType()
    {
        return PKCSObjectIdentifiers.data;
    }
}
