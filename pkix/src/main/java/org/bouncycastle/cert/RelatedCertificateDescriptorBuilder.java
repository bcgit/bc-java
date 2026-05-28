package org.bouncycastle.cert;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.bc.BCObjectIdentifiers;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.CertDiscoveryMethod;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.OtherName;
import org.bouncycastle.asn1.x509.RelatedCertificateDescriptor;

/**
 * Fluent builder for the {@link RelatedCertificateDescriptor} structure
 * defined by draft-ietf-lamps-certdiscovery, plus the wrapping required to
 * place it in a SubjectInfoAccess extension.
 *
 * <p>Typical use, adding a "fetch the agility companion over HTTP" entry to a
 * certificate's SubjectInfoAccess extension:</p>
 *
 * <pre>
 *     AccessDescription ad = new RelatedCertificateDescriptorBuilder()
 *         .setMethodByUri("https://example.com/companion.cer")
 *         .setIntent(BCObjectIdentifiers.id_rcd_agility)
 *         .setSignatureAlgorithm(sigAlg)
 *         .setPublicKeyAlgorithm(spkiAlg)
 *         .buildAccessDescription();
 *     // ad goes into a SEQUENCE OF AccessDescription added as the
 *     // SubjectInfoAccess extension on an X509v3CertificateBuilder.
 * </pre>
 *
 * @see RelatedCertificateDescriptor#fromExtensions(org.bouncycastle.asn1.x509.Extensions)
 */
public class RelatedCertificateDescriptorBuilder
{
    private CertDiscoveryMethod method;
    private ASN1ObjectIdentifier intent;
    private AlgorithmIdentifier signatureAlgorithm;
    private AlgorithmIdentifier publicKeyAlgorithm;

    public RelatedCertificateDescriptorBuilder setMethod(CertDiscoveryMethod method)
    {
        this.method = method;
        return this;
    }

    /**
     * Convenience for {@code setMethod(CertDiscoveryMethod.byUri(uri))}.
     */
    public RelatedCertificateDescriptorBuilder setMethodByUri(String uri)
    {
        return setMethod(CertDiscoveryMethod.byUri(uri));
    }

    /**
     * Convenience for {@code setMethod(CertDiscoveryMethod.byInclusion(cert))}.
     */
    public RelatedCertificateDescriptorBuilder setMethodByInclusion(X509CertificateHolder certificate)
    {
        return setMethod(CertDiscoveryMethod.byInclusion(certificate.toASN1Structure()));
    }

    /**
     * Convenience for {@code setMethod(CertDiscoveryMethod.byInclusion(cert))}.
     */
    public RelatedCertificateDescriptorBuilder setMethodByInclusion(Certificate certificate)
    {
        return setMethod(CertDiscoveryMethod.byInclusion(certificate));
    }

    /**
     * Convenience for {@code setMethod(CertDiscoveryMethod.byLocalPolicy())}.
     */
    public RelatedCertificateDescriptorBuilder setMethodByLocalPolicy()
    {
        return setMethod(CertDiscoveryMethod.byLocalPolicy());
    }

    /**
     * Set the optional DiscoveryIntentId (an OID under
     * {@link BCObjectIdentifiers#id_rcd}: agility, redundancy, dual,
     * privKeyStmt or self).
     */
    public RelatedCertificateDescriptorBuilder setIntent(ASN1ObjectIdentifier intent)
    {
        this.intent = intent;
        return this;
    }

    public RelatedCertificateDescriptorBuilder setSignatureAlgorithm(AlgorithmIdentifier signatureAlgorithm)
    {
        this.signatureAlgorithm = signatureAlgorithm;
        return this;
    }

    public RelatedCertificateDescriptorBuilder setPublicKeyAlgorithm(AlgorithmIdentifier publicKeyAlgorithm)
    {
        this.publicKeyAlgorithm = publicKeyAlgorithm;
        return this;
    }

    /**
     * Build the bare descriptor.
     */
    public RelatedCertificateDescriptor build()
    {
        if (method == null)
        {
            throw new IllegalStateException("'method' must be set before build()");
        }

        return new RelatedCertificateDescriptor(method, intent, signatureAlgorithm, publicKeyAlgorithm);
    }

    /**
     * Build an {@link AccessDescription} suitable for adding to a
     * SubjectInfoAccess extension: accessMethod is
     * {@link BCObjectIdentifiers#id_ad_certDiscovery}, accessLocation is an
     * {@code otherName} GeneralName whose type-id is
     * {@link BCObjectIdentifiers#id_on_relatedCertificateDescriptor} and
     * whose value is the descriptor built from the current builder state.
     */
    public AccessDescription buildAccessDescription()
    {
        OtherName otherName = new OtherName(
            BCObjectIdentifiers.id_on_relatedCertificateDescriptor,
            build());

        return new AccessDescription(
            BCObjectIdentifiers.id_ad_certDiscovery,
            new GeneralName(GeneralName.otherName, otherName));
    }
}
