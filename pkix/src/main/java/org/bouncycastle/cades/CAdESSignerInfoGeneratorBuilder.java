package org.bouncycastle.cades;

import java.io.IOException;
import java.io.OutputStream;
import java.util.Map;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.esf.CommitmentTypeIndication;
import org.bouncycastle.asn1.esf.SignaturePolicyIdentifier;
import org.bouncycastle.asn1.esf.SignerLocation;
import org.bouncycastle.asn1.ess.ContentHints;
import org.bouncycastle.asn1.ess.ESSCertID;
import org.bouncycastle.asn1.ess.ESSCertIDv2;
import org.bouncycastle.asn1.ess.SigningCertificate;
import org.bouncycastle.asn1.ess.SigningCertificateV2;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.IssuerSerial;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSAttributeTableGenerationException;
import org.bouncycastle.cms.CMSAttributeTableGenerator;
import org.bouncycastle.cms.SignerInfoGenerator;
import org.bouncycastle.cms.SignerInfoGeneratorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;

/**
 * Builds a {@link SignerInfoGenerator} for a CAdES B-B signature (ETSI
 * EN&nbsp;319&nbsp;122-1 / RFC&nbsp;5126 BES).
 * <p>
 * The builder injects the mandatory ESS signing-certificate reference into
 * the signed-attribute table and (optionally) any of the four signed
 * attributes defined by RFC&nbsp;5126 sec. 5.11:
 * commitment-type, signature-policy, signer-location and content-hints.
 * The default ESS reference uses the v2 form (RFC&nbsp;5035) with a SHA-256
 * digest; callers stuck with legacy interop can opt back into v1 via
 * {@link #setUseSigningCertificateV1(boolean)}, which forces a SHA-1 digest
 * per the v1 schema.
 * <p>
 * The class wraps the JCA-free
 * {@link org.bouncycastle.cms.SignerInfoGeneratorBuilder}; the
 * {@link DigestCalculatorProvider} supplied to the constructor is used both
 * for the signer&apos;s own message-digest calculations and for digesting
 * the signing certificate for the ESS reference, so callers can plug in
 * either the {@code Jca} or {@code Bc} flavour of provider as they prefer.
 * <p>
 * <pre>
 *      CAdESSignerInfoGeneratorBuilder b = new CAdESSignerInfoGeneratorBuilder(
 *          new JcaDigestCalculatorProviderBuilder().setProvider("BC").build());
 *      b.setCommitmentType(new CommitmentTypeIndication(
 *          CommitmentTypeIdentifier.proofOfOrigin));
 *      SignerInfoGenerator sig = b.build(contentSigner, signingCertHolder);
 *
 *      CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
 *      gen.addSignerInfoGenerator(sig);
 *      gen.addCertificate(signingCertHolder);
 *      CMSSignedData signed = gen.generate(new CMSProcessableByteArray(payload), true);
 * </pre>
 */
public class CAdESSignerInfoGeneratorBuilder
{
    private final SignerInfoGeneratorBuilder inner;
    private final DigestCalculatorProvider digestProvider;

    private boolean useV1 = false;
    /** Default ESS signing-certificate-v2 digest is SHA-256 (RFC 5035). */
    private AlgorithmIdentifier essCertDigest = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256);

    private CommitmentTypeIndication commitmentType;
    private SignaturePolicyIdentifier signaturePolicy;
    private SignerLocation signerLocation;
    private ContentHints contentHints;

    /**
     * @param digestProvider provider used both for the signer&apos;s own message-digest
     *                       calculations and for digesting the signing certificate.
     */
    public CAdESSignerInfoGeneratorBuilder(DigestCalculatorProvider digestProvider)
    {
        this.inner = new SignerInfoGeneratorBuilder(digestProvider);
        this.digestProvider = digestProvider;
    }

    /**
     * If set to true the builder emits the legacy ESS signing-certificate
     * attribute (RFC&nbsp;2634) with a SHA-1 digest instead of the modern
     * signing-certificate-v2 attribute (RFC&nbsp;5035). Default is false
     * (use the v2 form with SHA-256).
     */
    public CAdESSignerInfoGeneratorBuilder setUseSigningCertificateV1(boolean useV1)
    {
        this.useV1 = useV1;
        return this;
    }

    /**
     * Override the digest algorithm used for the ESS signing-certificate-v2
     * reference. Ignored when {@link #setUseSigningCertificateV1(boolean)}
     * is true (v1 is fixed to SHA-1).
     */
    public CAdESSignerInfoGeneratorBuilder setEssCertDigestAlgorithm(AlgorithmIdentifier digestAlgId)
    {
        if (digestAlgId == null)
        {
            throw new NullPointerException("digestAlgId");
        }
        this.essCertDigest = digestAlgId;
        return this;
    }

    /**
     * Set the optional {@code id-aa-ets-commitmentType} signed attribute
     * (RFC&nbsp;5126 sec. 5.11.1).
     */
    public CAdESSignerInfoGeneratorBuilder setCommitmentType(CommitmentTypeIndication commitmentType)
    {
        this.commitmentType = commitmentType;
        return this;
    }

    /**
     * Set the optional {@code id-aa-ets-sigPolicyId} signed attribute
     * (RFC&nbsp;5126 sec. 5.8.1).
     */
    public CAdESSignerInfoGeneratorBuilder setSignaturePolicy(SignaturePolicyIdentifier signaturePolicy)
    {
        this.signaturePolicy = signaturePolicy;
        return this;
    }

    /**
     * Set the optional {@code id-aa-ets-signerLocation} signed attribute
     * (RFC&nbsp;5126 sec. 5.11.2).
     */
    public CAdESSignerInfoGeneratorBuilder setSignerLocation(SignerLocation signerLocation)
    {
        this.signerLocation = signerLocation;
        return this;
    }

    /**
     * Set the optional {@code id-aa-contentHint} signed attribute
     * (RFC&nbsp;5126 sec. 5.10.2 / RFC&nbsp;2634).
     */
    public CAdESSignerInfoGeneratorBuilder setContentHints(ContentHints contentHints)
    {
        this.contentHints = contentHints;
        return this;
    }

    public SignerInfoGenerator build(ContentSigner contentSigner, final X509CertificateHolder certHolder)
        throws OperatorCreationException, CAdESException
    {
        final SignerInfoGenerator base = inner.build(contentSigner, certHolder);

        final Attribute essCertAttr = buildSigningCertificateAttribute(certHolder);

        CMSAttributeTableGenerator outer = new CMSAttributeTableGenerator()
        {
            public AttributeTable getAttributes(Map parameters)
                throws CMSAttributeTableGenerationException
            {
                AttributeTable table = base.getSignedAttributeTableGenerator().getAttributes(parameters);

                if (table.get(essCertAttr.getAttrType()) == null)
                {
                    table = table.add(essCertAttr.getAttrType(),
                        (ASN1Encodable)essCertAttr.getAttrValues().getObjectAt(0));
                }

                if (commitmentType != null && table.get(PKCSObjectIdentifiers.id_aa_ets_commitmentType) == null)
                {
                    table = table.add(PKCSObjectIdentifiers.id_aa_ets_commitmentType, commitmentType);
                }
                if (signaturePolicy != null && table.get(PKCSObjectIdentifiers.id_aa_ets_sigPolicyId) == null)
                {
                    table = table.add(PKCSObjectIdentifiers.id_aa_ets_sigPolicyId, signaturePolicy);
                }
                if (signerLocation != null && table.get(PKCSObjectIdentifiers.id_aa_ets_signerLocation) == null)
                {
                    table = table.add(PKCSObjectIdentifiers.id_aa_ets_signerLocation, signerLocation);
                }
                if (contentHints != null && table.get(PKCSObjectIdentifiers.id_aa_contentHint) == null)
                {
                    table = table.add(PKCSObjectIdentifiers.id_aa_contentHint, contentHints);
                }

                return table;
            }
        };

        return new SignerInfoGenerator(base, outer, base.getUnsignedAttributeTableGenerator());
    }

    private Attribute buildSigningCertificateAttribute(X509CertificateHolder cert)
        throws CAdESException
    {
        IssuerSerial issuerSerial = new IssuerSerial(
            new GeneralNames(new GeneralName(cert.getIssuer())),
            new ASN1Integer(cert.getSerialNumber()));

        byte[] encoded;
        try
        {
            encoded = cert.getEncoded();
        }
        catch (IOException e)
        {
            throw new CAdESException("cannot encode signing certificate: " + e.getMessage(), e);
        }

        if (useV1)
        {
            byte[] hash = digest(new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1), encoded);
            ESSCertID essCertID = new ESSCertID(hash, issuerSerial);
            return new Attribute(PKCSObjectIdentifiers.id_aa_signingCertificate,
                new DERSet(new SigningCertificate(essCertID)));
        }
        else
        {
            byte[] hash = digest(essCertDigest, encoded);
            // ESSCertIDv2 ctor leaves the algorithm-identifier absent when the
            // digest is SHA-256 (RFC 5035's DEFAULT); otherwise emit it explicitly.
            ASN1ObjectIdentifier oid = essCertDigest.getAlgorithm();
            ESSCertIDv2 essCertIDv2 = NISTObjectIdentifiers.id_sha256.equals(oid)
                ? new ESSCertIDv2(hash, issuerSerial)
                : new ESSCertIDv2(new AlgorithmIdentifier(oid), hash, issuerSerial);
            return new Attribute(PKCSObjectIdentifiers.id_aa_signingCertificateV2,
                new DERSet(new SigningCertificateV2(essCertIDv2)));
        }
    }

    private byte[] digest(AlgorithmIdentifier digestAlg, byte[] data)
        throws CAdESException
    {
        DigestCalculator dc;
        try
        {
            dc = digestProvider.get(digestAlg);
        }
        catch (OperatorCreationException e)
        {
            throw new CAdESException("digest algorithm " + digestAlg.getAlgorithm().getId()
                + " not available in provider", e);
        }
        try
        {
            OutputStream out = dc.getOutputStream();
            out.write(data);
            out.close();
        }
        catch (IOException e)
        {
            throw new CAdESException("digest failed: " + e.getMessage(), e);
        }
        return dc.getDigest();
    }
}
