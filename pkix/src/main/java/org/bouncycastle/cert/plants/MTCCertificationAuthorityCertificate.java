package org.bouncycastle.cert.plants;

import java.io.IOException;
import java.math.BigInteger;
import java.util.Date;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1RelativeOID;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.plants.MTCObjectIdentifiers;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.MTCCertificationAuthority;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;

/**
 * Helpers for the CA certificate representation defined by Section 5.5 of
 * draft-ietf-plants-merkle-tree-certs.
 *
 * <p>A Merkle Tree CA is represented as an X.509 certificate whose:</p>
 * <ul>
 *   <li>{@code subject} is the CA ID encoded as a single-RDN distinguished name,
 *       using {@link MTCObjectIdentifiers#id_rdna_trustAnchorID} with a
 *       UTF8String value of the dotted-decimal trust anchor ID</li>
 *   <li>{@code subjectPublicKeyInfo} is the CA cosigner's public key</li>
 *   <li>{@code extensions} carries a critical
 *       {@link MTCObjectIdentifiers#id_pe_mtcCertificationAuthority}
 *       extension whose value is the {@link MTCCertificationAuthority} structure</li>
 *   <li>{@code keyUsage} (critical) asserts at least {@code keyCertSign}</li>
 *   <li>{@code basicConstraints} (critical) sets {@code cA=true}</li>
 *   <li>{@code subjectKeyIdentifier} (when present) SHOULD be the binary CA ID</li>
 * </ul>
 *
 * <p>Per Section 5.5 such certificates SHOULD NOT be self-signed; they are
 * typically distributed as unsigned trust anchors. This helper does not sign
 * the certificate &mdash; the caller supplies a {@link org.bouncycastle.operator.ContentSigner}
 * to {@link X509v3CertificateBuilder#build} when finishing the chain (e.g. an
 * unsigned-cert signer per draft-ietf-lamps-x509-alg-none, or an external CA).</p>
 */
public final class MTCCertificationAuthorityCertificate
{
    /** OID for the {@code id-pe-mtcCertificationAuthority} certificate extension. */
    public static final ASN1ObjectIdentifier EXTENSION_OID = MTCObjectIdentifiers.id_pe_mtcCertificationAuthority;

    private MTCCertificationAuthorityCertificate()
    {
    }

    /**
     * Builds the {@code subject} (or {@code issuer}) distinguished name for a
     * CA whose binary trust anchor ID is {@code caId}, using the experimental
     * encoding from Section 5.1.
     */
    public static X500Name subjectName(byte[] caId)
    {
        String dotted = TrustAnchorIDs.toDottedDecimal(caId);
        AttributeTypeAndValue attr = new AttributeTypeAndValue(
            MTCObjectIdentifiers.id_rdna_trustAnchorID,
            new DERUTF8String(dotted));
        return new X500Name(new RDN[]{new RDN(attr)});
    }

    /**
     * Builds the critical {@code id-pe-mtcCertificationAuthority} extension.
     */
    public static Extension buildAuthorityExtension(MTCCertificationAuthority info)
        throws IOException
    {
        return new Extension(EXTENSION_OID, true, info.getEncoded());
    }

    /**
     * Prepares a fully-populated {@link X509v3CertificateBuilder} for an MTC CA
     * certificate. The caller must invoke
     * {@link X509v3CertificateBuilder#build(org.bouncycastle.operator.ContentSigner) build}
     * with an appropriate signer (e.g. an unsigned-cert signer, or an external
     * CA signer).
     *
     * @param issuer       the X.509 issuer (often the same as {@code subject}
     *                     when the trust anchor is self-attested, or the OID
     *                     of the chaining CA)
     * @param serial       certificate serial number
     * @param notBefore    validity start
     * @param notAfter     validity end
     * @param caId         binary CA trust anchor ID
     * @param cosignerSpki the cosigner's SubjectPublicKeyInfo
     * @param info         the {@link MTCCertificationAuthority} extension value
     */
    public static X509v3CertificateBuilder newBuilder(
        X500Name issuer,
        BigInteger serial,
        Date notBefore,
        Date notAfter,
        byte[] caId,
        SubjectPublicKeyInfo cosignerSpki,
        MTCCertificationAuthority info)
        throws IOException
    {
        X500Name subject = subjectName(caId);
        X509v3CertificateBuilder builder = new X509v3CertificateBuilder(
            issuer, serial, notBefore, notAfter, subject, cosignerSpki);

        builder.addExtension(buildAuthorityExtension(info));
        builder.addExtension(Extension.keyUsage, true,
            new KeyUsage(KeyUsage.keyCertSign));
        builder.addExtension(Extension.basicConstraints, true,
            new BasicConstraints(true));
        builder.addExtension(Extension.subjectKeyIdentifier, false,
            new SubjectKeyIdentifier(caId));

        return builder;
    }

    /**
     * Extracts the binary CA trust anchor ID from the {@code subject} field of
     * a CA certificate. The encoding rules mirror
     * {@link MerkleTreeCertificateValidator#extractCaIdFromIssuer}, which reads
     * the equivalent attribute from the {@code issuer} field of a Merkle Tree
     * end-entity certificate.
     */
    public static byte[] extractCaId(X509CertificateHolder cert)
        throws IOException
    {
        X500Name subject = cert.getSubject();
        RDN[] rdns = subject.getRDNs();
        if (rdns.length != 1)
        {
            throw new IOException("CA certificate subject must have exactly one RDN");
        }
        AttributeTypeAndValue[] atav = rdns[0].getTypesAndValues();
        if (atav.length != 1)
        {
            throw new IOException("CA certificate RDN must have exactly one attribute");
        }
        if (!MTCObjectIdentifiers.id_rdna_trustAnchorID.equals(atav[0].getType()))
        {
            throw new IOException("Subject attribute is not id-rdna-trustAnchorID");
        }

        ASN1Encodable value = atav[0].getValue();
        ASN1Primitive prim = value.toASN1Primitive();
        if (prim instanceof ASN1RelativeOID)
        {
            return TrustAnchorIDs.fromDottedDecimal(((ASN1RelativeOID)prim).getId());
        }
        if (prim instanceof ASN1String)
        {
            return TrustAnchorIDs.fromDottedDecimal(((ASN1String)prim).getString());
        }
        throw new IOException("Unsupported attribute value type: " + prim.getClass().getName());
    }

    /**
     * Extracts the {@link MTCCertificationAuthority} structure from the
     * {@code id-pe-mtcCertificationAuthority} extension of a CA certificate.
     *
     * @throws IOException if the extension is absent, not marked critical, or
     *                     cannot be parsed
     */
    public static MTCCertificationAuthority extractAuthorityInfo(X509CertificateHolder cert)
        throws IOException
    {
        Extensions exts = cert.getExtensions();
        if (exts == null)
        {
            throw new IOException("CA certificate has no extensions");
        }
        Extension ext = exts.getExtension(EXTENSION_OID);
        if (ext == null)
        {
            throw new IOException("CA certificate is missing the id-pe-mtcCertificationAuthority extension");
        }
        if (!ext.isCritical())
        {
            throw new IOException("id-pe-mtcCertificationAuthority extension must be critical");
        }
        return MTCCertificationAuthority.getInstance(ext.getParsedValue());
    }
}
