package org.bouncycastle.asn1.cms;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.BERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

/**
 * <a href="https://tools.ietf.org/html/rfc5652#section-9.1">RFC 5652</a> section 9.1:
 * The AuthenticatedData carries AuthAttributes and other data
 * which define what really is being signed.
 * <pre>
 * AuthenticatedData ::= SEQUENCE {
 *       version CMSVersion,
 *       originatorInfo [0] IMPLICIT OriginatorInfo OPTIONAL,
 *       recipientInfos RecipientInfos,
 *       macAlgorithm MessageAuthenticationCodeAlgorithm,
 *       digestAlgorithm [1] DigestAlgorithmIdentifier OPTIONAL,
 *       encapContentInfo EncapsulatedContentInfo,
 *       authAttrs [2] IMPLICIT AuthAttributes OPTIONAL,
 *       mac MessageAuthenticationCode,
 *       unauthAttrs [3] IMPLICIT UnauthAttributes OPTIONAL }
 *
 * AuthAttributes ::= SET SIZE (1..MAX) OF Attribute
 *
 * UnauthAttributes ::= SET SIZE (1..MAX) OF Attribute
 *
 * MessageAuthenticationCode ::= OCTET STRING
 * </pre>
 */
public class AuthenticatedData
    extends ASN1Object
{
    private ASN1Integer version;
    private OriginatorInfo originatorInfo;
    private ASN1Set recipientInfos;
    private AlgorithmIdentifier macAlgorithm;
    private AlgorithmIdentifier digestAlgorithm;
    private ContentInfo encapsulatedContentInfo;
    private ASN1Set authAttrs;
    private ASN1OctetString mac;
    private ASN1Set unauthAttrs;

    public AuthenticatedData(
        OriginatorInfo originatorInfo,
        ASN1Set recipientInfos,
        AlgorithmIdentifier macAlgorithm,
        AlgorithmIdentifier digestAlgorithm,
        ContentInfo encapsulatedContent,
        ASN1Set authAttrs,
        ASN1OctetString mac,
        ASN1Set unauthAttrs)
    {
        if (digestAlgorithm != null || authAttrs != null)
        {
            if (digestAlgorithm == null || authAttrs == null)
            {
                throw new IllegalArgumentException("digestAlgorithm and authAttrs must be set together");
            }
        }

        version = new ASN1Integer(calculateVersion(originatorInfo));
        
        this.originatorInfo = originatorInfo;
        this.macAlgorithm = macAlgorithm;
        this.digestAlgorithm = digestAlgorithm;
        this.recipientInfos = recipientInfos;
        this.encapsulatedContentInfo = encapsulatedContent;
        this.authAttrs = authAttrs;
        this.mac = mac;
        this.unauthAttrs = unauthAttrs;
    }

    private AuthenticatedData(
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
        macAlgorithm = AlgorithmIdentifier.getInstance(seq.getObjectAt(index++));

        tmp = seq.getObjectAt(index++);

        if (tmp instanceof ASN1TaggedObject)
        {
            digestAlgorithm = AlgorithmIdentifier.getInstance((ASN1TaggedObject)tmp, false);
            tmp = seq.getObjectAt(index++);
        }

        encapsulatedContentInfo = ContentInfo.getInstance(tmp);

        tmp = seq.getObjectAt(index++);

        if (tmp instanceof ASN1TaggedObject)
        {
            authAttrs = ASN1Set.getInstance((ASN1TaggedObject)tmp, false);
            tmp = seq.getObjectAt(index++);
        }

        mac = ASN1OctetString.getInstance(tmp);
        
        if (seq.size() > index)
        {
            unauthAttrs = ASN1Set.getInstance((ASN1TaggedObject)seq.getObjectAt(index), false);
        }
    }

    /**
     * Return an AuthenticatedData object from a tagged object.
     *
     * @param obj      the tagged object holding the object we want.
     * @param explicit true if the object is meant to be explicitly
     *                 tagged false otherwise.
     * @return a reference that can be assigned to AuthenticatedData (may be null)
     * @throws IllegalArgumentException if the object held by the
     *                                  tagged object cannot be converted.
     */
    public static AuthenticatedData getInstance(
        ASN1TaggedObject obj,
        boolean explicit)
    {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    /**
     * Return an AuthenticatedData object from the given object.
     * <p>
     * Accepted inputs:
     * <ul>
     * <li> null &rarr; null
     * <li> {@link AuthenticatedData} object
     * <li> {@link org.bouncycastle.asn1.ASN1Sequence#getInstance(java.lang.Object) ASN1Sequence} input formats with AuthenticatedData structure inside
     * </ul>
     *
     * @param obj the object we want converted.
     * @return a reference that can be assigned to AuthenticatedData (may be null)
     * @throws IllegalArgumentException if the object cannot be converted.
     */
    public static AuthenticatedData getInstance(
        Object obj)
    {
        if (obj instanceof AuthenticatedData)
        {
            return (AuthenticatedData)obj;
        }
        else if (obj != null)
        {
            return new AuthenticatedData(ASN1Sequence.getInstance(obj));
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

    public AlgorithmIdentifier getMacAlgorithm()
    {
        return macAlgorithm;
    }

    public AlgorithmIdentifier getDigestAlgorithm()
    {
        return digestAlgorithm;
    }

    public ContentInfo getEncapsulatedContentInfo()
    {
        return encapsulatedContentInfo;
    }

    public ASN1Set getAuthAttrs()
    {
        return authAttrs;
    }

    public ASN1OctetString getMac()
    {
        return mac;
    }

    public ASN1Set getUnauthAttrs()
    {
        return unauthAttrs;
    }

    /**
     * Produce an object suitable for an ASN1OutputStream.
     */
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector(9);

        v.add(version);

        if (originatorInfo != null)
        {
            v.add(new DERTaggedObject(false, 0, originatorInfo));
        }

        v.add(recipientInfos);
        v.add(macAlgorithm);

        if (digestAlgorithm != null)
        {
            v.add(new DERTaggedObject(false, 1, digestAlgorithm));
        }

        v.add(encapsulatedContentInfo);

        if (authAttrs != null)
        {
            v.add(new DERTaggedObject(false, 2, authAttrs));
        }

        v.add(mac);

        if (unauthAttrs != null)
        {
            v.add(new DERTaggedObject(false, 3, unauthAttrs));
        }

        return new BERSequence(v);
    }

    public static int calculateVersion(OriginatorInfo origInfo)
    {
        /*
         * IF (originatorInfo is present) AND
         *    ((any certificates with a type of other are present) OR
         *    (any crls with a type of other are present))
         * THEN version is 3
         * ELSE
         *    IF ((originatorInfo is present) AND
         *       (any version 2 attribute certificates are present))
         *    THEN version is 1
         *    ELSE version is 0
         */

        if (origInfo != null)
        {
            ASN1Set crls = origInfo.getCRLs();
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
                            return 3;
                        }
                    }
                }
            }

            ASN1Set certs = origInfo.getCertificates();
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
                            return 3;
                        }

                        // CertificateChoices.v2AttrCert
                        anyV2AttrCerts = anyV2AttrCerts || tagged.hasContextTag(2);
                    }
                }

                if (anyV2AttrCerts)
                {
                    return 1;
                }
            }
        }
        return 0;
    }
}
