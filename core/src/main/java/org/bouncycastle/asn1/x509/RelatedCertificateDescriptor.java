package org.bouncycastle.asn1.x509;

import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.bc.BCObjectIdentifiers;

/**
 * Descriptor for a related certificate, as defined by
 * draft-ietf-lamps-certdiscovery-04 (A Mechanism for X.509 Certificate Discovery).
 * Carried as the value of an {@link OtherName} (type-id
 * {@link BCObjectIdentifiers#id_on_relatedCertificateDescriptor}) inside the
 * {@code accessLocation} GeneralName of an {@link AccessDescription} whose
 * {@code accessMethod} is
 * {@link BCObjectIdentifiers#id_ad_certDiscovery}, sitting in turn inside
 * the SubjectInfoAccess extension ({@link Extension#subjectInfoAccess}).
 *
 * <pre>
 *     RelatedCertificateDescriptor ::= SEQUENCE {
 *         method               CertDiscoveryMethod,
 *         signatureAlgorithm   [0] AlgorithmIdentifier{SIGNATURE-ALGORITHM, {...}} OPTIONAL,
 *         publicKeyAlgorithm   [1] AlgorithmIdentifier{PUBLIC-KEY, {...}} OPTIONAL,
 *         certHash             [2] RelatedCertificate OPTIONAL
 *     }
 * </pre>
 *
 * The module is defined with EXPLICIT TAGS, so the three optional fields are
 * explicitly tagged. {@code certHash} is the RFC 9763 {@link RelatedCertificate}
 * structure, a hash over the entire Referenced Certificate. The draft requires
 * that none of the optional fields is present when the method is
 * {@code byInclusion}; this class carries what it is given and leaves that
 * rule to the caller.
 */
public class RelatedCertificateDescriptor
    extends ASN1Object
{
    private final CertDiscoveryMethod method;
    private final AlgorithmIdentifier signatureAlgorithm;
    private final AlgorithmIdentifier publicKeyAlgorithm;
    private final RelatedCertificate certHash;

    public RelatedCertificateDescriptor(
        CertDiscoveryMethod method,
        AlgorithmIdentifier signatureAlgorithm,
        AlgorithmIdentifier publicKeyAlgorithm,
        RelatedCertificate certHash)
    {
        if (method == null)
        {
            throw new NullPointerException("'method' cannot be null");
        }

        this.method = method;
        this.signatureAlgorithm = signatureAlgorithm;
        this.publicKeyAlgorithm = publicKeyAlgorithm;
        this.certHash = certHash;
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

        AlgorithmIdentifier signatureAlgorithm = null;
        if (pos < count)
        {
            ASN1TaggedObject tag0 = ASN1TaggedObject.getContextOptional(seq.getObjectAt(pos), 0);
            if (tag0 != null)
            {
                pos++;
                signatureAlgorithm = AlgorithmIdentifier.getInstance(tag0, true);
            }
        }

        AlgorithmIdentifier publicKeyAlgorithm = null;
        if (pos < count)
        {
            ASN1TaggedObject tag1 = ASN1TaggedObject.getContextOptional(seq.getObjectAt(pos), 1);
            if (tag1 != null)
            {
                pos++;
                publicKeyAlgorithm = AlgorithmIdentifier.getInstance(tag1, true);
            }
        }

        RelatedCertificate certHash = null;
        if (pos < count)
        {
            ASN1TaggedObject tag2 = ASN1TaggedObject.getContextOptional(seq.getObjectAt(pos), 2);
            if (tag2 != null)
            {
                pos++;
                certHash = RelatedCertificate.getInstance(ASN1Sequence.getInstance(tag2, true));
            }
        }

        if (pos != count)
        {
            throw new IllegalArgumentException("unexpected element at position " + pos);
        }

        this.signatureAlgorithm = signatureAlgorithm;
        this.publicKeyAlgorithm = publicKeyAlgorithm;
        this.certHash = certHash;
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

    public AlgorithmIdentifier getSignatureAlgorithm()
    {
        return signatureAlgorithm;
    }

    public AlgorithmIdentifier getPublicKeyAlgorithm()
    {
        return publicKeyAlgorithm;
    }

    /**
     * Return the RFC 9763 hash of the Referenced Certificate, or {@code null}
     * if absent.
     */
    public RelatedCertificate getCertHash()
    {
        return certHash;
    }

    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector(4);

        v.add(method);

        if (signatureAlgorithm != null)
        {
            v.add(new DERTaggedObject(true, 0, signatureAlgorithm));
        }
        if (publicKeyAlgorithm != null)
        {
            v.add(new DERTaggedObject(true, 1, publicKeyAlgorithm));
        }
        if (certHash != null)
        {
            v.add(new DERTaggedObject(true, 2, certHash));
        }

        return new DERSequence(v);
    }
}
