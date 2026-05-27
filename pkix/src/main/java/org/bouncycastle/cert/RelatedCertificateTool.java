package org.bouncycastle.cert;

import java.io.IOException;
import java.io.OutputStream;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.BinaryTime;
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.asn1.cms.RequesterCertificate;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.RelatedCertificate;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.ContentVerifier;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.util.Arrays;

/**
 * Operator-style helpers for building and verifying the two wire-format
 * pieces defined by RFC 9763 ("Related Certificates for Use in Multiple
 * Authentications within a Protocol"):
 *
 * <ul>
 *   <li>the {@link RelatedCertificate} certificate extension carried on an
 *       end-entity certificate (OID
 *       {@link org.bouncycastle.asn1.x509.X509ObjectIdentifiers#id_pe_relatedCert}
 *       / {@link org.bouncycastle.asn1.x509.Extension#relatedCertificate}), and</li>
 *   <li>the {@link RequesterCertificate} CSR attribute value the requester
 *       includes in the CSR to prove they hold the private key of the related
 *       certificate (attribute OID
 *       {@link PKCSObjectIdentifiers#id_aa_relatedCertRequest}).</li>
 * </ul>
 *
 * <p>The intended use case is post-quantum migration: an end entity that
 * already holds a traditional certificate requests a parallel post-quantum
 * certificate by including a {@code id-aa-relatedCertRequest} attribute in
 * the new CSR; the CA verifies the requester controls both private keys,
 * then issues the new certificate carrying a {@code RelatedCertificate}
 * extension that pins the traditional certificate by digest. A verifier
 * seeing both certificates can then assert with assurance that they
 * identify the same principal.
 *
 * <p>This class is JCA-free and lightweight-crypto-free: it consumes
 * {@link DigestCalculator} / {@link DigestCalculatorProvider} /
 * {@link ContentSigner} / {@link ContentVerifier} from
 * {@code org.bouncycastle.operator}, so both the lightweight (BC) and JCA
 * bindings of those operator interfaces are equally usable. Wrapping /
 * unwrapping the value as a PKCS#9 {@link org.bouncycastle.asn1.pkcs.Attribute}
 * lives on the value class itself — see {@link RequesterCertificate#toAttribute()}
 * and {@link RequesterCertificate#fromAttribute(org.bouncycastle.asn1.pkcs.Attribute)}.
 */
public class RelatedCertificateTool
{
    private RelatedCertificateTool()
    {
        // utility class
    }

    // =====================================================================
    // RelatedCertificate extension
    // =====================================================================

    /**
     * Compute the {@link RelatedCertificate} extension value identifying the
     * supplied certificate by digest. Per RFC 9763 sec. 3.2 the digest input
     * is the DER encoding of the entire {@code Certificate} structure (i.e.
     * the value returned by {@link X509CertificateHolder#getEncoded()}).
     *
     * @param relatedCert      the related end-entity certificate to bind.
     * @param digestCalculator a calculator configured for the desired digest
     *                         algorithm; its
     *                         {@link DigestCalculator#getAlgorithmIdentifier()
     *                         AlgorithmIdentifier} is copied verbatim into the
     *                         extension's {@code hashAlgorithm} field.
     * @throws IOException if the related certificate cannot be encoded or the
     *                     digest calculator's output stream rejects bytes.
     */
    public static RelatedCertificate createRelatedCertificate(
        X509CertificateHolder relatedCert,
        DigestCalculator digestCalculator)
        throws IOException
    {
        if (relatedCert == null)
        {
            throw new NullPointerException("'relatedCert' cannot be null");
        }
        if (digestCalculator == null)
        {
            throw new NullPointerException("'digestCalculator' cannot be null");
        }

        OutputStream dOut = digestCalculator.getOutputStream();
        relatedCert.toASN1Structure().encodeTo(dOut, ASN1Encoding.DER);
        dOut.close();

        return new RelatedCertificate(
            digestCalculator.getAlgorithmIdentifier(),
            DEROctetString.fromContents(digestCalculator.getDigest()));
    }

    /**
     * Recompute the digest specified in a {@link RelatedCertificate} extension
     * value over the supplied candidate certificate and report whether it
     * matches the stored hash.
     *
     * @param extensionValue    the parsed {@code RelatedCertificate} extension
     *                          value, e.g. via
     *                          {@code RelatedCertificate.getInstance(ext.getParsedValue())}.
     * @param relatedCert       the candidate related certificate.
     * @param digestProvider    a provider able to instantiate a
     *                          {@link DigestCalculator} for the
     *                          {@code hashAlgorithm} carried by
     *                          {@code extensionValue}.
     */
    public static boolean isRelatedCertificate(
        RelatedCertificate extensionValue,
        X509CertificateHolder relatedCert,
        DigestCalculatorProvider digestProvider)
        throws OperatorCreationException, IOException
    {
        if (extensionValue == null)
        {
            throw new NullPointerException("'extensionValue' cannot be null");
        }
        if (relatedCert == null)
        {
            throw new NullPointerException("'relatedCert' cannot be null");
        }
        if (digestProvider == null)
        {
            throw new NullPointerException("'digestProvider' cannot be null");
        }

        DigestCalculator digester = digestProvider.get(extensionValue.getHashAlgorithm());

        OutputStream dOut = digester.getOutputStream();
        relatedCert.toASN1Structure().encodeTo(dOut, ASN1Encoding.DER);
        dOut.close();

        return Arrays.constantTimeAreEqual(extensionValue.getHashValue().getOctets(), digester.getDigest());
    }

    // =====================================================================
    // RequesterCertificate CSR attribute
    // =====================================================================

    /**
     * Write the bytes the {@link RequesterCertificate#getSignature() signature}
     * field must cover straight into {@code out}: the DER encoding of
     * {@code certID} followed by the DER encoding of {@code requestTime}, per
     * RFC 9763 sec. 4.1 ("concatenation of DER-encoded IssuerAndSerialNumber
     * and BinaryTime"). This is NOT wrapped in an outer SEQUENCE —
     * implementations that hash a SEQUENCE will fail to interoperate. The two
     * structures are streamed directly so no intermediate {@code byte[]} is
     * materialised; pass a {@link ContentSigner} / {@link ContentVerifier}
     * output stream (or a {@code ByteArrayOutputStream} if you need the bytes).
     */
    public static void writeSignatureInput(OutputStream out, IssuerAndSerialNumber certID, BinaryTime requestTime)
        throws IOException
    {
        if (out == null)
        {
            throw new NullPointerException("'out' cannot be null");
        }
        if (certID == null)
        {
            throw new NullPointerException("'certID' cannot be null");
        }
        if (requestTime == null)
        {
            throw new NullPointerException("'requestTime' cannot be null");
        }
        certID.encodeTo(out, ASN1Encoding.DER);
        requestTime.encodeTo(out, ASN1Encoding.DER);
    }

    /**
     * Build a fully-signed {@link RequesterCertificate} value. The supplied
     * {@link ContentSigner} must be configured with the private key of the
     * certificate identified by {@code certID}.
     */
    public static RequesterCertificate createRequesterCertificate(
        IssuerAndSerialNumber certID,
        BinaryTime requestTime,
        String[] locationInfo,
        ContentSigner signer)
        throws IOException
    {
        if (signer == null)
        {
            throw new NullPointerException("'signer' cannot be null");
        }

        OutputStream sOut = signer.getOutputStream();
        writeSignatureInput(sOut, certID, requestTime);
        sOut.close();

        return new RequesterCertificate(certID, requestTime, locationInfo, signer.getSignature());
    }

    /**
     * Verify the signature carried in {@code value} using the supplied
     * {@link ContentVerifier}. The verifier must be configured with the public
     * key of the certificate identified by {@code value.getCertID()} and the
     * signature algorithm the CSR signer used (RFC 9763 carries no
     * AlgorithmIdentifier with the signature, so the caller must derive it
     * from the related certificate's SPKI plus any local policy).
     */
    public static boolean verifyRequesterCertificate(RequesterCertificate value, ContentVerifier verifier)
        throws IOException
    {
        if (value == null)
        {
            throw new NullPointerException("'value' cannot be null");
        }
        if (verifier == null)
        {
            throw new NullPointerException("'verifier' cannot be null");
        }

        OutputStream vOut = verifier.getOutputStream();
        writeSignatureInput(vOut, value.getCertID(), value.getRequestTime());
        vOut.close();

        return verifier.verify(value.getSignature().getOctets());
    }

    // =====================================================================
    // PKCS#9 attribute wrapping
    // =====================================================================

    /**
     * Wrap a {@code RequesterCertificate} value as a PKCS#9 {@link Attribute}
     * carrying {@link PKCSObjectIdentifiers#id_aa_relatedCertRequest}, ready to
     * drop into a {@code CertificationRequestInfo} attributes set.
     */
    public static Attribute toAttribute(RequesterCertificate value)
    {
        if (value == null)
        {
            throw new NullPointerException("'value' cannot be null");
        }
        return new Attribute(PKCSObjectIdentifiers.id_aa_relatedCertRequest, new DERSet(value));
    }

    /**
     * Extract a {@code RequesterCertificate} value from a PKCS#9
     * {@link Attribute}.
     *
     * @throws IllegalArgumentException if the attribute is not of type
     *         {@link PKCSObjectIdentifiers#id_aa_relatedCertRequest} or does
     *         not carry exactly one value.
     */
    public static RequesterCertificate fromAttribute(Attribute attribute)
    {
        if (attribute == null)
        {
            throw new NullPointerException("'attribute' cannot be null");
        }
        if (!PKCSObjectIdentifiers.id_aa_relatedCertRequest.equals(attribute.getAttrType()))
        {
            throw new IllegalArgumentException(
                "'attribute' type expected id-aa-relatedCertRequest but got " + attribute.getAttrType());
        }
        if (attribute.getAttributeValues().length != 1)
        {
            throw new IllegalArgumentException(
                "'attribute' for id-aa-relatedCertRequest must carry exactly one value, got "
                    + attribute.getAttributeValues().length);
        }
        return RequesterCertificate.getInstance(attribute.getAttributeValues()[0]);
    }
}
