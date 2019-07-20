package org.bouncycastle.asn1.bc;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.DigestInfo;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;

/**
 * Extension to tie an alternate certificate to the containing certificate.
 * <pre>
 *     LinkedCertificate := SEQUENCE {
 *         digest        DigestInfo,                   -- digest of PQC certificate
 *         certLocation  GeneralName,                  -- location of PQC certificate
 *         certIssuer    [0] Name OPTIONAL,            -- issuer of PQC cert (if different from current certificate)
 *         cACerts       [1] GeneralNames OPTIONAL,    -- CA certificates for PQC cert (one of more locations)
 * }
 * </pre>
 */
public class LinkedCertificate
    extends ASN1Object
{
    private final DigestInfo digest;
    private final GeneralName certLocation;

    private X500Name certIssuer;
    private GeneralNames cACerts;

    public LinkedCertificate(DigestInfo digest, GeneralName certLocation)
    {
        this(digest, certLocation, null, null);
    }

    public LinkedCertificate(DigestInfo digest, GeneralName certLocation, X500Name certIssuer, GeneralNames cACerts)
    {
        this.digest = digest;
        this.certLocation = certLocation;
        this.certIssuer = certIssuer;
        this.cACerts = cACerts;
    }

    private LinkedCertificate(ASN1Sequence seq)
    {
        this.digest = DigestInfo.getInstance(seq.getObjectAt(0));
        this.certLocation = GeneralName.getInstance(seq.getObjectAt(1));

        if (seq.size() > 2)
        {
            for (int i = 2; i != seq.size(); i++)
            {
                ASN1TaggedObject tagged =  ASN1TaggedObject.getInstance(seq.getObjectAt(i));

                switch (tagged.getTagNo())
                {
                case 0:
                    certIssuer = X500Name.getInstance(tagged, false);
                    break;
                case 1:
                    cACerts = GeneralNames.getInstance(tagged, false);
                    break;
                default:
                    throw new IllegalArgumentException("unknown tag in tagged field");
                }
            }
        }
    }

    public static LinkedCertificate getInstance(Object o)
    {
        if (o instanceof LinkedCertificate)
        {
            return (LinkedCertificate)o;
        }
        else if (o != null)
        {
            return new LinkedCertificate(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public DigestInfo getDigest()
    {
        return digest;
    }

    public GeneralName getCertLocation()
    {
        return certLocation;
    }

    public X500Name getCertIssuer()
    {
        return certIssuer;
    }

    public GeneralNames getCACerts()
    {
        return cACerts;
    }

    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector(4);

        v.add(digest);
        v.add(certLocation);

        if (certIssuer != null)
        {
            v.add(new DERTaggedObject(false, 0, certIssuer));
        }
        if (cACerts != null)
        {
            v.add(new DERTaggedObject(false, 1, cACerts));
        }

        return new DERSequence(v);
    }
}
