package org.bouncycastle.asn1.pkcs;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.BERSequence;
import org.bouncycastle.asn1.DERTaggedObject;

/**
 * a PKCS#7 signed data object.
 */
public class SignedData
    extends ASN1Object
    implements PKCSObjectIdentifiers
{
    private ASN1Integer              version;
    private ASN1Set                 digestAlgorithms;
    private ContentInfo             contentInfo;
    private ASN1Set                 certificates;
    private ASN1Set                 crls;
    private ASN1Set                 signerInfos;

    public static SignedData getInstance(
        Object  o)
    {
        if (o instanceof SignedData)
        {
            return (SignedData)o;
        }
        else if (o != null)
        {
            return new SignedData(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public SignedData(
        ASN1Integer        _version,
        ASN1Set           _digestAlgorithms,
        ContentInfo       _contentInfo,
        ASN1Set           _certificates,
        ASN1Set           _crls,
        ASN1Set           _signerInfos)
    {
        version          = _version;
        digestAlgorithms = _digestAlgorithms;
        contentInfo      = _contentInfo;
        certificates     = _certificates;
        crls             = _crls;
        signerInfos      = _signerInfos;
    }

    public SignedData(
        ASN1Sequence seq)
    {
        int count = seq.size(), pos = 0;
        if (count < 3)
        {
            throw new IllegalArgumentException("Bad sequence size: " + count);
        }

        version = ASN1Integer.getInstance(seq.getObjectAt(pos++));
        digestAlgorithms = ASN1Set.getInstance(seq.getObjectAt(pos++));
        contentInfo = ContentInfo.getInstance(seq.getObjectAt(pos++));

        // certificates [0] and crls [1], each optional, then signerInfos
        if (pos < count)
        {
            ASN1TaggedObject tag0 = ASN1TaggedObject.getContextOptional(seq.getObjectAt(pos), 0);
            if (tag0 != null)
            {
                pos++;
                certificates = ASN1Set.getInstance(tag0, false);
            }
        }
        if (pos < count)
        {
            ASN1TaggedObject tag1 = ASN1TaggedObject.getContextOptional(seq.getObjectAt(pos), 1);
            if (tag1 != null)
            {
                pos++;
                crls = ASN1Set.getInstance(tag1, false);
            }
        }
        // signerInfos is required, but its absence has always been tolerated; nothing may follow it
        if (pos < count && !(seq.getObjectAt(pos).toASN1Primitive() instanceof ASN1TaggedObject))
        {
            signerInfos = ASN1Set.getInstance(seq.getObjectAt(pos++));
        }

        if (pos != count)
        {
            throw new IllegalArgumentException("unexpected element at position " + pos);
        }
    }

    public ASN1Integer getVersion()
    {
        return version;
    }

    public ASN1Set getDigestAlgorithms()
    {
        return digestAlgorithms;
    }

    public ContentInfo getContentInfo()
    {
        return contentInfo;
    }

    public ASN1Set getCertificates()
    {
        return certificates;
    }

    public ASN1Set getCRLs()
    {
        return crls;
    }

    public ASN1Set getSignerInfos()
    {
        return signerInfos;
    }

    /**
     * Produce an object suitable for an ASN1OutputStream.
     * <pre>
     *  SignedData ::= SEQUENCE {
     *      version Version,
     *      digestAlgorithms DigestAlgorithmIdentifiers,
     *      contentInfo ContentInfo,
     *      certificates
     *          [0] IMPLICIT ExtendedCertificatesAndCertificates
     *                   OPTIONAL,
     *      crls
     *          [1] IMPLICIT CertificateRevocationLists OPTIONAL,
     *      signerInfos SignerInfos }
     * </pre>
     */
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector(6);

        v.add(version);
        v.add(digestAlgorithms);
        v.add(contentInfo);

        if (certificates != null)
        {
            v.add(new DERTaggedObject(false, 0, certificates));
        }

        if (crls != null)
        {
            v.add(new DERTaggedObject(false, 1, crls));
        }

        v.add(signerInfos);

        return new BERSequence(v);
    }
}
