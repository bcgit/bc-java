package org.bouncycastle.asn1.x509;

import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.bc.BCObjectIdentifiers;

/**
 * Descriptor for a related certificate, as defined by
 * draft-ietf-lamps-certdiscovery (Certificate Discovery in PKIX). Carried as
 * the value of an {@link OtherName} (type-id
 * {@link BCObjectIdentifiers#id_on_relatedCertificateDescriptor}) inside the
 * {@code accessLocation} GeneralName of an {@link AccessDescription} whose
 * {@code accessMethod} is
 * {@link BCObjectIdentifiers#id_ad_certDiscovery}, sitting in turn inside
 * the SubjectInfoAccess extension ({@link Extension#subjectInfoAccess}).
 *
 * <pre>
 *     RelatedCertificateDescriptor ::= SEQUENCE {
 *         method               CertDiscoveryMethod,
 *         intent               DiscoveryIntentId OPTIONAL,
 *         signatureAlgorithm   [0] IMPLICIT AlgorithmIdentifier OPTIONAL,
 *         publicKeyAlgorithm   [1] IMPLICIT AlgorithmIdentifier OPTIONAL
 *     }
 *
 *     DiscoveryIntentId ::= OBJECT IDENTIFIER
 * </pre>
 *
 * Intent OIDs are defined under {@link BCObjectIdentifiers#id_rcd} (placeholder
 * arc pending IANA assignment): {@link BCObjectIdentifiers#id_rcd_agility},
 * {@link BCObjectIdentifiers#id_rcd_redundancy},
 * {@link BCObjectIdentifiers#id_rcd_dual},
 * {@link BCObjectIdentifiers#id_rcd_priv_key_stmt},
 * {@link BCObjectIdentifiers#id_rcd_self}.
 */
public class RelatedCertificateDescriptor
    extends ASN1Object
{
    private final CertDiscoveryMethod method;
    private final ASN1ObjectIdentifier intent;
    private final AlgorithmIdentifier signatureAlgorithm;
    private final AlgorithmIdentifier publicKeyAlgorithm;

    public RelatedCertificateDescriptor(
        CertDiscoveryMethod method,
        ASN1ObjectIdentifier intent,
        AlgorithmIdentifier signatureAlgorithm,
        AlgorithmIdentifier publicKeyAlgorithm)
    {
        if (method == null)
        {
            throw new NullPointerException("'method' cannot be null");
        }

        this.method = method;
        this.intent = intent;
        this.signatureAlgorithm = signatureAlgorithm;
        this.publicKeyAlgorithm = publicKeyAlgorithm;
    }

    public RelatedCertificateDescriptor(CertDiscoveryMethod method)
    {
        this(method, null, null, null);
    }

    private RelatedCertificateDescriptor(ASN1Sequence seq)
    {
        if (seq.size() < 1)
        {
            throw new IllegalArgumentException("sequence may not be empty");
        }

        this.method = CertDiscoveryMethod.getInstance(seq.getObjectAt(0));

        ASN1ObjectIdentifier intent = null;
        AlgorithmIdentifier signatureAlgorithm = null;
        AlgorithmIdentifier publicKeyAlgorithm = null;

        for (int i = 1; i < seq.size(); i++)
        {
            ASN1Encodable element = seq.getObjectAt(i);
            ASN1Primitive prim = element.toASN1Primitive();

            if (prim instanceof ASN1ObjectIdentifier)
            {
                if (intent != null)
                {
                    throw new IllegalArgumentException("duplicate intent OID in RelatedCertificateDescriptor");
                }
                intent = (ASN1ObjectIdentifier)prim;
            }
            else if (prim instanceof ASN1TaggedObject)
            {
                ASN1TaggedObject tagged = (ASN1TaggedObject)prim;
                switch (tagged.getTagNo())
                {
                case 0:
                    if (signatureAlgorithm != null)
                    {
                        throw new IllegalArgumentException("duplicate signatureAlgorithm in RelatedCertificateDescriptor");
                    }
                    signatureAlgorithm = AlgorithmIdentifier.getInstance(tagged, false);
                    break;
                case 1:
                    if (publicKeyAlgorithm != null)
                    {
                        throw new IllegalArgumentException("duplicate publicKeyAlgorithm in RelatedCertificateDescriptor");
                    }
                    publicKeyAlgorithm = AlgorithmIdentifier.getInstance(tagged, false);
                    break;
                default:
                    throw new IllegalArgumentException("unknown tag in RelatedCertificateDescriptor: " + tagged.getTagNo());
                }
            }
            else
            {
                throw new IllegalArgumentException("unexpected element in RelatedCertificateDescriptor: " + prim.getClass().getName());
            }
        }

        this.intent = intent;
        this.signatureAlgorithm = signatureAlgorithm;
        this.publicKeyAlgorithm = publicKeyAlgorithm;
    }

    public static RelatedCertificateDescriptor getInstance(Object obj)
    {
        if (obj == null || obj instanceof RelatedCertificateDescriptor)
        {
            return (RelatedCertificateDescriptor)obj;
        }

        return new RelatedCertificateDescriptor(ASN1Sequence.getInstance(obj));
    }

    /**
     * Walk the SubjectInfoAccess extension of the supplied {@link Extensions}
     * and return every {@link RelatedCertificateDescriptor} it carries (each
     * AccessDescription whose accessMethod is
     * {@link BCObjectIdentifiers#id_ad_certDiscovery} and whose accessLocation
     * is an OtherName of type
     * {@link BCObjectIdentifiers#id_on_relatedCertificateDescriptor}).
     *
     * @return an array, never {@code null}; empty when the extension is
     *         absent or carries no certificate-discovery descriptors.
     */
    public static RelatedCertificateDescriptor[] fromExtensions(Extensions extensions)
    {
        ASN1Encodable extValue = Extensions.getExtensionParsedValue(extensions, Extension.subjectInfoAccess);
        if (extValue == null)
        {
            return new RelatedCertificateDescriptor[0];
        }

        AccessDescription[] descriptions = AuthorityInformationAccess.getInstance(extValue).getAccessDescriptions();

        List collected = new ArrayList();
        for (int i = 0; i != descriptions.length; i++)
        {
            AccessDescription ad = descriptions[i];
            if (!BCObjectIdentifiers.id_ad_certDiscovery.equals(ad.getAccessMethod()))
            {
                continue;
            }

            GeneralName accessLocation = ad.getAccessLocation();
            if (accessLocation == null || accessLocation.getTagNo() != GeneralName.otherName)
            {
                continue;
            }

            OtherName otherName = OtherName.getInstance(accessLocation.getName());
            if (!BCObjectIdentifiers.id_on_relatedCertificateDescriptor.equals(otherName.getTypeID()))
            {
                continue;
            }

            collected.add(getInstance(otherName.getValue()));
        }

        return (RelatedCertificateDescriptor[])collected.toArray(new RelatedCertificateDescriptor[collected.size()]);
    }

    public CertDiscoveryMethod getMethod()
    {
        return method;
    }

    public ASN1ObjectIdentifier getIntent()
    {
        return intent;
    }

    public AlgorithmIdentifier getSignatureAlgorithm()
    {
        return signatureAlgorithm;
    }

    public AlgorithmIdentifier getPublicKeyAlgorithm()
    {
        return publicKeyAlgorithm;
    }

    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector(4);

        v.add(method);

        if (intent != null)
        {
            v.add(intent);
        }
        if (signatureAlgorithm != null)
        {
            v.add(new DERTaggedObject(false, 0, signatureAlgorithm));
        }
        if (publicKeyAlgorithm != null)
        {
            v.add(new DERTaggedObject(false, 1, publicKeyAlgorithm));
        }

        return new DERSequence(v);
    }
}
