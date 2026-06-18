package org.bouncycastle.pkcs;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;

/**
 * Builder for the delta certificate request attribute defined in
 * draft-bonnell-lamps-chameleon-certs §5.
 * <pre>
 * DeltaCertificateRequestValue ::= SEQUENCE {
 *   subject               [0] EXPLICIT Name OPTIONAL,
 *   subjectPKInfo         SubjectPublicKeyInfo,
 *   extensions            [1] EXPLICIT Extensions OPTIONAL,
 *   signatureAlgorithm    [2] EXPLICIT AlgorithmIdentifier OPTIONAL
 * }
 * </pre>
 * The builder emits every field the caller set; to encode only the fields that
 * differ from a base CSR (§5.1), pass the result through
 * {@link DeltaCertAttributeUtils#trimDeltaCertificateRequest}.
 */
public class DeltaCertificateRequestAttributeValueBuilder
{
    static final ASN1ObjectIdentifier deltaCertificateRequest = new ASN1ObjectIdentifier("2.16.840.1.114027.80.6.2");

    private final SubjectPublicKeyInfo subjectPublicKey;

    private AlgorithmIdentifier signatureAlgorithm;
    private X500Name subject;
    private Extensions extensions;

    /**
     * Base constructor.
     *
     * @param subjectPublicKey the alternate public key committed to by the delta request.
     */
    public DeltaCertificateRequestAttributeValueBuilder(SubjectPublicKeyInfo subjectPublicKey)
    {
        this.subjectPublicKey = subjectPublicKey;
    }

    /**
     * Set the signature algorithm declared in the delta request; when unset the delta request
     * reuses the base request's signature algorithm.
     *
     * @param signatureAlgorithm the signature algorithm identifier.
     * @return this builder.
     */
    public DeltaCertificateRequestAttributeValueBuilder setSignatureAlgorithm(AlgorithmIdentifier signatureAlgorithm)
    {
        this.signatureAlgorithm = signatureAlgorithm;

        return this;
    }

    /**
     * Set the subject declared in the delta request; when unset the delta request reuses the
     * base request's subject.
     *
     * @param subject the subject distinguished name.
     * @return this builder.
     */
    public DeltaCertificateRequestAttributeValueBuilder setSubject(X500Name subject)
    {
        this.subject = subject;

        return this;
    }

    /**
     * Set the extensions declared in the delta request.
     *
     * @param extensions the extensions to attach to the delta request.
     * @return this builder.
     */
    public DeltaCertificateRequestAttributeValueBuilder setExtensions(Extensions extensions)
    {
        this.extensions = extensions;

        return this;
    }

    /**
     * Build the configured {@link DeltaCertificateRequestAttributeValue}.
     *
     * @return the resulting attribute value.
     */
    public DeltaCertificateRequestAttributeValue build()
    {
        ASN1EncodableVector v = new ASN1EncodableVector(4);

        if (subject != null)
        {
            v.add(new DERTaggedObject(true, 0, subject));
        }
        v.add(subjectPublicKey);
        if (extensions != null)
        {
            v.add(new DERTaggedObject(true, 1, extensions));
        }
        if (signatureAlgorithm != null)
        {
            v.add(new DERTaggedObject(true, 2, signatureAlgorithm));
        }

        return new DeltaCertificateRequestAttributeValue(
            new Attribute(deltaCertificateRequest, new DERSet(new DERSequence(v))));
    }
}
