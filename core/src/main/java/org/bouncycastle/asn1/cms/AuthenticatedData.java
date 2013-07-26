package org.bouncycastle.asn1.cms;

import java.util.Enumeration;

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
 * <a href="http://tools.ietf.org/html/rfc5652#section-9.1">RFC 5652</a> section 9.1:
 * The AuthenticatedData carries {@link AuthAttributes authAttrs} and other data
 * which define what really is being signed.
 * <p>
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

    public AuthenticatedData(
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
     * @throws IllegalArgumentException if the object cannot be converted.
     */
    public static AuthenticatedData getInstance(
        Object obj)
    {
        if (obj == null || obj instanceof AuthenticatedData)
        {
            return (AuthenticatedData)obj;
        }

        if (obj instanceof ASN1Sequence)
        {
            return new AuthenticatedData((ASN1Sequence)obj);
        }

        throw new IllegalArgumentException("Invalid AuthenticatedData: " + obj.getClass().getName());
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
        ASN1EncodableVector v = new ASN1EncodableVector();

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
        if (origInfo == null)
        {
            return 0;
        }
        else
        {
            int ver = 0;

            for (Enumeration e = origInfo.getCertificates().getObjects(); e.hasMoreElements();)
            {
                Object obj = e.nextElement();

                if (obj instanceof ASN1TaggedObject)
                {
                    ASN1TaggedObject tag = (ASN1TaggedObject)obj;

                    if (tag.getTagNo() == 2)
                    {
                        ver = 1;
                    }
                    else if (tag.getTagNo() == 3)
                    {
                        ver = 3;
                        break;
                    }
                }
            }

            if (origInfo.getCRLs() != null)
            {
                for (Enumeration e = origInfo.getCRLs().getObjects(); e.hasMoreElements();)
                {
                    Object obj = e.nextElement();

                    if (obj instanceof ASN1TaggedObject)
                    {
                        ASN1TaggedObject tag = (ASN1TaggedObject)obj;

                        if (tag.getTagNo() == 1)
                        {
                            ver = 3;
                            break;
                        }
                    }
                }
            }

            return ver;
        }
    }
}
