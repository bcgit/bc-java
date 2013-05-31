package org.bouncycastle.cms;

import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.asn1.cms.OriginatorInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.util.Store;

public class OriginatorInfoGenerator
{
    private List origCerts;
    private List origCRLs;

    public OriginatorInfoGenerator(X509CertificateHolder origCert)
    {
        this.origCerts = new ArrayList(1);
        this.origCRLs = null;
        origCerts.add(origCert.toASN1Structure());
    }

    public OriginatorInfoGenerator(Store origCerts)
        throws CMSException
    {
        this(origCerts, null);
    }

    public OriginatorInfoGenerator(Store origCerts, Store origCRLs)
        throws CMSException
    {
        this.origCerts = CMSUtils.getCertificatesFromStore(origCerts);

        if (origCRLs != null)
        {
            this.origCRLs = CMSUtils.getCRLsFromStore(origCRLs);
        }
        else
        {
            this.origCRLs = null;
        }
    }

    public OriginatorInformation generate()
    {
        if (origCRLs != null)
        {
            return new OriginatorInformation(new OriginatorInfo(CMSUtils.createDerSetFromList(origCerts), CMSUtils.createDerSetFromList(origCRLs)));
        }
        else
        {
            return new OriginatorInformation(new OriginatorInfo(CMSUtils.createDerSetFromList(origCerts), null));
        }
    }
}
