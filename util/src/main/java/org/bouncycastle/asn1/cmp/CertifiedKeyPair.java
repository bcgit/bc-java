package org.bouncycastle.asn1.cmp;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.BERTags;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.crmf.EncryptedKey;
import org.bouncycastle.asn1.crmf.EncryptedValue;
import org.bouncycastle.asn1.crmf.PKIPublicationInfo;

/**
 * <pre>
 * CertifiedKeyPair ::= SEQUENCE {
 *                                  certOrEncCert       CertOrEncCert,
 *                                  privateKey      [0] EncryptedKey      OPTIONAL,
 *                                  -- see [CRMF] for comment on encoding
 *                                  publicationInfo [1] PKIPublicationInfo  OPTIONAL
 *       }
 * </pre>
 */
public class CertifiedKeyPair
    extends ASN1Object
{
    private final CertOrEncCert certOrEncCert;
    private EncryptedKey privateKey;
    private PKIPublicationInfo publicationInfo;

    private CertifiedKeyPair(ASN1Sequence seq)
    {
        if (seq.size() < 1 || seq.size() > 3)
        {
            throw new IllegalArgumentException("Bad sequence size: " + seq.size());
        }

        certOrEncCert = CertOrEncCert.getInstance(seq.getObjectAt(0));

        // privateKey [0] and publicationInfo [1], each optional, in that order
        int lastTagNo = -1;
        for (int i = 1; i < seq.size(); i++)
        {
            ASN1TaggedObject tagged = ASN1TaggedObject.getInstance(seq.getObjectAt(i), BERTags.CONTEXT_SPECIFIC);
            if (tagged.getTagNo() <= lastTagNo)
            {
                throw new IllegalArgumentException("tag [" + tagged.getTagNo() + "] repeated or out of order");
            }
            lastTagNo = tagged.getTagNo();

            if (tagged.getTagNo() == 0)
            {
                privateKey = EncryptedKey.getInstance(tagged.getExplicitBaseObject());
            }
            else if (tagged.getTagNo() == 1)
            {
                publicationInfo = PKIPublicationInfo.getInstance(tagged.getExplicitBaseObject());
            }
            else
            {
                throw new IllegalArgumentException("unknown tag: " + tagged.getTagNo());
            }
        }
    }

    public CertifiedKeyPair(
        CertOrEncCert certOrEncCert)
    {
        this(certOrEncCert, (EncryptedKey)null, null);
    }

    public CertifiedKeyPair(
        CertOrEncCert certOrEncCert,
        EncryptedKey privateKey,
        PKIPublicationInfo publicationInfo)
    {
        if (certOrEncCert == null)
        {
            throw new IllegalArgumentException("'certOrEncCert' cannot be null");
        }

        this.certOrEncCert = certOrEncCert;
        this.privateKey = privateKey;
        this.publicationInfo = publicationInfo;
    }

    public CertifiedKeyPair(
        CertOrEncCert certOrEncCert,
        EncryptedValue privateKey,
        PKIPublicationInfo publicationInfo)
    {
        if (certOrEncCert == null)
        {
            throw new IllegalArgumentException("'certOrEncCert' cannot be null");
        }

        this.certOrEncCert = certOrEncCert;
        this.privateKey = (privateKey != null) ? new EncryptedKey(privateKey) : null;
        this.publicationInfo = publicationInfo;
    }

    public static CertifiedKeyPair getInstance(Object o)
    {
        if (o instanceof CertifiedKeyPair)
        {
            return (CertifiedKeyPair)o;
        }

        if (o != null)
        {
            return new CertifiedKeyPair(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public CertOrEncCert getCertOrEncCert()
    {
        return certOrEncCert;
    }

    public EncryptedKey getPrivateKey()
    {
        return privateKey;
    }

    public PKIPublicationInfo getPublicationInfo()
    {
        return publicationInfo;
    }

    /**
     * Return the primitive representation of PKIPublicationInfo.
     *
     * @return a basic ASN.1 object representation.
     */
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector(3);

        v.add(certOrEncCert);

        if (privateKey != null)
        {
            v.add(new DERTaggedObject(true, 0, privateKey));
        }

        if (publicationInfo != null)
        {
            v.add(new DERTaggedObject(true, 1, publicationInfo));
        }

        return new DERSequence(v);
    }
}
