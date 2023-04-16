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
        certOrEncCert = CertOrEncCert.getInstance(seq.getObjectAt(0));

        if (seq.size() >= 2)
        {
            if (seq.size() == 2)
            {
                ASN1TaggedObject tagged = ASN1TaggedObject.getInstance(seq.getObjectAt(1), BERTags.CONTEXT_SPECIFIC);
                if (tagged.getTagNo() == 0)
                {
                    privateKey = EncryptedKey.getInstance(tagged.getExplicitBaseObject());
                }
                else
                {
                    publicationInfo = PKIPublicationInfo.getInstance(tagged.getExplicitBaseObject());
                }
            }
            else
            {
                privateKey = EncryptedKey.getInstance(ASN1TaggedObject.getInstance(seq.getObjectAt(1), BERTags.CONTEXT_SPECIFIC).getExplicitBaseObject());
                publicationInfo = PKIPublicationInfo.getInstance(ASN1TaggedObject.getInstance(seq.getObjectAt(2), BERTags.CONTEXT_SPECIFIC).getExplicitBaseObject());
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
