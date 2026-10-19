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

        int count = seq.size(), pos = 1;

        ASN1ObjectIdentifier intent = null;
        if (pos < count && seq.getObjectAt(pos).toASN1Primitive() instanceof ASN1ObjectIdentifier)
        {
            intent = ASN1ObjectIdentifier.getInstance(seq.getObjectAt(pos++));
        }

        AlgorithmIdentifier signatureAlgorithm = null;
        if (pos < count)
        {
            ASN1TaggedObject tag0 = ASN1TaggedObject.getContextOptional(seq.getObjectAt(pos), 0);
            if (tag0 != null)
            {
                pos++;
                signatureAlgorithm = AlgorithmIdentifier.getInstance(tag0, false);
            }
        }

        AlgorithmIdentifier publicKeyAlgorithm = null;
        if (pos < count)
        {
            ASN1TaggedObject tag1 = ASN1TaggedObject.getContextOptional(seq.getObjectAt(pos), 1);
            if (tag1 != null)
            {
                pos++;
                publicKeyAlgorithm = AlgorithmIdentifier.getInstance(tag1, false);
            }
        }

        if (pos != count)
        {
            throw new IllegalArgumentException("unexpected element at position " + pos);
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
