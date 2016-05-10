package com.github.gv2011.bcasn.asn1.cmp;

import com.github.gv2011.bcasn.asn1.ASN1EncodableVector;
import com.github.gv2011.bcasn.asn1.ASN1GeneralizedTime;
import com.github.gv2011.bcasn.asn1.ASN1Object;
import com.github.gv2011.bcasn.asn1.ASN1Primitive;
import com.github.gv2011.bcasn.asn1.ASN1Sequence;
import com.github.gv2011.bcasn.asn1.DERSequence;
import com.github.gv2011.bcasn.asn1.crmf.CertId;
import com.github.gv2011.bcasn.asn1.x509.Extensions;

public class RevAnnContent
    extends ASN1Object
{
    private PKIStatus status;
    private CertId certId;
    private ASN1GeneralizedTime willBeRevokedAt;
    private ASN1GeneralizedTime badSinceDate;
    private Extensions crlDetails;
    
    private RevAnnContent(ASN1Sequence seq)
    {
        status = PKIStatus.getInstance(seq.getObjectAt(0));
        certId = CertId.getInstance(seq.getObjectAt(1));
        willBeRevokedAt = ASN1GeneralizedTime.getInstance(seq.getObjectAt(2));
        badSinceDate = ASN1GeneralizedTime.getInstance(seq.getObjectAt(3));

        if (seq.size() > 4)
        {
            crlDetails = Extensions.getInstance(seq.getObjectAt(4));
        }
    }

    public static RevAnnContent getInstance(Object o)
    {
        if (o instanceof RevAnnContent)
        {
            return (RevAnnContent)o;
        }

        if (o != null)
        {
            return new RevAnnContent(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public PKIStatus getStatus()
    {
        return status;
    }

    public CertId getCertId()
    {
        return certId;
    }

    public ASN1GeneralizedTime getWillBeRevokedAt()
    {
        return willBeRevokedAt;
    }

    public ASN1GeneralizedTime getBadSinceDate()
    {
        return badSinceDate;
    }

    public Extensions getCrlDetails()
    {
        return crlDetails;
    }

    /**
     * <pre>
     * RevAnnContent ::= SEQUENCE {
     *       status              PKIStatus,
     *       certId              CertId,
     *       willBeRevokedAt     GeneralizedTime,
     *       badSinceDate        GeneralizedTime,
     *       crlDetails          Extensions  OPTIONAL
     *        -- extra CRL details (e.g., crl number, reason, location, etc.)
     * }
     * </pre>
     * @return a basic ASN.1 object representation.
     */
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(status);
        v.add(certId);
        v.add(willBeRevokedAt);
        v.add(badSinceDate);

        if (crlDetails != null)
        {
            v.add(crlDetails);
        }

        return new DERSequence(v);
    }
}
