package org.bouncycastle.asn1.cms;

import org.bouncycastle.asn1.ASN1Encodable;
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
 * <a href="https://tools.ietf.org/html/rfc5652#section-6.1">RFC 5652</a> EnvelopedData object.
 * <pre>
 * EnvelopedData ::= SEQUENCE {
 *     version CMSVersion,
 *     originatorInfo [0] IMPLICIT OriginatorInfo OPTIONAL,
 *     recipientInfos RecipientInfos,
 *     encryptedContentInfo EncryptedContentInfo,
 *     unprotectedAttrs [1] IMPLICIT UnprotectedAttributes OPTIONAL
 * }
 * </pre>
 */
public class EnvelopedData
    extends ASN1Object
{
    private ASN1Integer version;
    private OriginatorInfo originatorInfo;
    private ASN1Set recipientInfos;
    private EncryptedContentInfo encryptedContentInfo;
    private ASN1Set unprotectedAttrs;

    public EnvelopedData(
        OriginatorInfo originatorInfo,
        ASN1Set recipientInfos,
        EncryptedContentInfo encryptedContentInfo,
        ASN1Set unprotectedAttrs)
    {
        version = new ASN1Integer(calculateVersion(originatorInfo, recipientInfos, unprotectedAttrs));

        this.originatorInfo = originatorInfo;
        this.recipientInfos = recipientInfos;
        this.encryptedContentInfo = encryptedContentInfo;
        this.unprotectedAttrs = unprotectedAttrs;
    }

    public EnvelopedData(
        OriginatorInfo originatorInfo,
        ASN1Set recipientInfos,
        EncryptedContentInfo encryptedContentInfo,
        Attributes unprotectedAttrs)
    {
        version = new ASN1Integer(calculateVersion(originatorInfo, recipientInfos, ASN1Set.getInstance(unprotectedAttrs)));

        this.originatorInfo = originatorInfo;
        this.recipientInfos = recipientInfos;
        this.encryptedContentInfo = encryptedContentInfo;
        this.unprotectedAttrs = ASN1Set.getInstance(unprotectedAttrs);
    }

    private EnvelopedData(
        ASN1Sequence seq)
    {
        int index = 0;

        version = (ASN1Integer)seq.getObjectAt(index++);

        Object tmp = seq.getObjectAt(index++);

        if (tmp instanceof ASN1TaggedObject)
        {
            originatorInfo = OriginatorInfo.getInstance((ASN1TaggedObject)tmp, false);
            tmp = seq.getObjectAt(index++);
        }

        recipientInfos = ASN1Set.getInstance(tmp);

        encryptedContentInfo = EncryptedContentInfo.getInstance(seq.getObjectAt(index++));

        if (seq.size() > index)
        {
            unprotectedAttrs = ASN1Set.getInstance((ASN1TaggedObject)seq.getObjectAt(index), false);
        }
    }

    /**
     * Return an EnvelopedData object from a tagged object.
     *
     * @param obj      the tagged object holding the object we want.
     * @param explicit true if the object is meant to be explicitly
     *                 tagged false otherwise.
     * @throws IllegalArgumentException if the object held by the
     *                                  tagged object cannot be converted.
     */
    public static EnvelopedData getInstance(
        ASN1TaggedObject obj,
        boolean explicit)
    {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    /**
     * Return an EnvelopedData object from the given object.
     * <p>
     * Accepted inputs:
     * <ul>
     * <li> null &rarr; null
     * <li> {@link EnvelopedData} object
     * <li> {@link org.bouncycastle.asn1.ASN1Sequence#getInstance(java.lang.Object) ASN1Sequence} input formats with EnvelopedData structure inside
     * </ul>
     *
     * @param obj the object we want converted.
     * @throws IllegalArgumentException if the object cannot be converted.
     */
    public static EnvelopedData getInstance(
        Object obj)
    {
        if (obj instanceof EnvelopedData)
        {
            return (EnvelopedData)obj;
        }

        if (obj != null)
        {
            return new EnvelopedData(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    public ASN1Integer getVersion()
    {
        return version;
    }

    public OriginatorInfo getOriginatorInfo()
    {
        return originatorInfo;
    }

    public ASN1Set getRecipientInfos()
    {
        return recipientInfos;
    }

    public EncryptedContentInfo getEncryptedContentInfo()
    {
        return encryptedContentInfo;
    }

    public ASN1Set getUnprotectedAttrs()
    {
        return unprotectedAttrs;
    }

    /**
     * Produce an object suitable for an ASN1OutputStream.
     */
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector(5);

        v.add(version);

        if (originatorInfo != null)
        {
            v.add(new DERTaggedObject(false, 0, originatorInfo));
        }

        v.add(recipientInfos);
        v.add(encryptedContentInfo);

        if (unprotectedAttrs != null)
        {
            v.add(new DERTaggedObject(false, 1, unprotectedAttrs));
        }

        return new BERSequence(v);
    }

    public static int calculateVersion(OriginatorInfo originatorInfo, ASN1Set recipientInfos, ASN1Set unprotectedAttrs)
    {
        /*
         * IF (originatorInfo is present) AND
         *    ((any certificates with a type of other are present) OR
         *    (any crls with a type of other are present))
         * THEN version is 4
         * ELSE
         *    IF ((originatorInfo is present) AND
         *       (any version 2 attribute certificates are present)) OR
         *       (any RecipientInfo structures include pwri) OR
         *       (any RecipientInfo structures include ori)
         *    THEN version is 3
         *    ELSE
         *       IF (originatorInfo is absent) AND
         *          (unprotectedAttrs is absent) AND
         *          (all RecipientInfo structures are version 0)
         *       THEN version is 0
         *       ELSE version is 2
         */

        if (originatorInfo != null)
        {
            ASN1Set crls = originatorInfo.getCRLs();
            if (crls != null)
            {
                for (int i = 0, count = crls.size(); i < count; ++i)
                {
                    ASN1Encodable element = crls.getObjectAt(i);
                    if (element instanceof ASN1TaggedObject)
                    {
                        ASN1TaggedObject tagged = (ASN1TaggedObject)element;

                        // RevocationInfoChoice.other
                        if (tagged.hasContextTag(1))
                        {
                            return 4;
                        }
                    }
                }
            }

            ASN1Set certs = originatorInfo.getCertificates();
            if (certs != null)
            {
                boolean anyV2AttrCerts = false;

                for (int i = 0, count = certs.size(); i < count; ++i)
                {
                    ASN1Encodable element = certs.getObjectAt(i);
                    if (element instanceof ASN1TaggedObject)
                    {
                        ASN1TaggedObject tagged = (ASN1TaggedObject)element;

                        // CertificateChoices.other
                        if (tagged.hasContextTag(3))
                        {
                            return 4;
                        }

                        // CertificateChoices.v2AttrCert
                        anyV2AttrCerts = anyV2AttrCerts || tagged.hasContextTag(2);
                    }
                }

                if (anyV2AttrCerts)
                {
                    return 3;
                }
            }
        }

        boolean allV0Recipients = true;
        for (int i = 0, count = recipientInfos.size(); i < count; ++i)
        {
            RecipientInfo recipientInfo = RecipientInfo.getInstance(recipientInfos.getObjectAt(i));

            // (any RecipientInfo structures include pwri) OR
            // (any RecipientInfo structures include ori)
            if (recipientInfo.isPasswordOrOther())
            {
                return 3;
            }

            // (all RecipientInfo structures are version 0)
            // -- 'kari.version' is always 3
            // -- 'kekri.version' is always 4
            // -- 'pwri' and 'ori' have already been excluded
            allV0Recipients = allV0Recipients && recipientInfo.isKeyTransV0();
        }

        if (originatorInfo == null && unprotectedAttrs == null && allV0Recipients)
        {
            return 0;
        }

        return 2;
    }
}
