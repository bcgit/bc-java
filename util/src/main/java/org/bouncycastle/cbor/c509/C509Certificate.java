package org.bouncycastle.cbor.c509;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.Date;
import java.util.Locale;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.TBSCertificate;
import org.bouncycastle.asn1.x509.Time;
import org.bouncycastle.asn1.x509.V3TBSCertificateGenerator;
import org.bouncycastle.cbor.CBORDecoder;
import org.bouncycastle.cbor.CBOREncoder;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.Exceptions;

/**
 * A C509 certificate (Section 3 of draft-ietf-cose-cbor-encoded-cert-20):
 * <pre>
 * C509Certificate = [ TBSCertificate, issuerSignatureValue: any ]
 * </pre>
 * where the ten elements of the TBSCertificate group are inlined into the array, and
 * for a natively signed certificate the signature is computed over their encoding as
 * a CBOR sequence (RFC 8742).
 * <p>
 * Two certificate types are supported: natively signed C509 certificates
 * ({@link #TYPE_NATIVE}), where the signature covers the CBOR itself, and CBOR
 * re-encoded X.509 v3 DER certificates ({@link #TYPE_REENCODED_X509}), where the
 * signature is copied from the DER encoding and remains verifiable only over the
 * reconstructed DER, available from {@link #toX509Certificate()}.
 * <p>
 * All fields are validated and their X.509 views materialized at parse time, and only
 * deterministically encoded input in the forms this class itself produces is
 * accepted, so for every accepted encoding {@code getInstance(enc).getEncoded()} is
 * byte identical to {@code enc}. Conversion from X.509 with
 * {@link #fromX509Certificate(Certificate, C509ConversionOptions)} is gated on exact
 * invertibility: if re-encoding the resulting C509 certificate does not reproduce the
 * input DER byte for byte, the conversion is refused rather than allowed to produce a
 * certificate whose signature could never verify.
 */
public class C509Certificate
{
    /** Natively signed C509 certificate (c509CertificateType = 2). */
    public static final int TYPE_NATIVE = 2;
    /** CBOR re-encoded X.509 v3 DER certificate (c509CertificateType = 3). */
    public static final int TYPE_REENCODED_X509 = 3;

    /**
     * The validityNotAfter value standing for the GeneralizedTime 99991231235959Z,
     * "no well-defined expiration date" (RFC 5280 Section 4.1.2.5), carried in C509 as
     * the CBOR simple value null.
     */
    public static final long NO_EXPIRATION_DATE = 253402300799L;

    private final int certificateType;
    private final byte[] serialNumber;
    private final C509AlgorithmIdentifier issuerSignatureAlgorithm;
    private final C509Name issuer;
    private final long notBefore;
    private final long notAfter;
    private final C509Name subject;
    private final C509AlgorithmIdentifier subjectPublicKeyAlgorithm;
    private final byte[] subjectPublicKeyItem;
    private final SubjectPublicKeyInfo subjectPublicKeyInfo;
    private final C509Extensions extensions;
    private final byte[] signatureValueItem;
    private final byte[] signature;

    private C509Certificate(int certificateType, byte[] serialNumber,
        C509AlgorithmIdentifier issuerSignatureAlgorithm, C509Name issuer, long notBefore, long notAfter,
        C509Name subject, C509AlgorithmIdentifier subjectPublicKeyAlgorithm, byte[] subjectPublicKeyItem,
        SubjectPublicKeyInfo subjectPublicKeyInfo, C509Extensions extensions, byte[] signatureValueItem,
        byte[] signature)
    {
        this.certificateType = certificateType;
        this.serialNumber = serialNumber;
        this.issuerSignatureAlgorithm = issuerSignatureAlgorithm;
        this.issuer = issuer;
        this.notBefore = notBefore;
        this.notAfter = notAfter;
        this.subject = subject;
        this.subjectPublicKeyAlgorithm = subjectPublicKeyAlgorithm;
        this.subjectPublicKeyItem = subjectPublicKeyItem;
        this.subjectPublicKeyInfo = subjectPublicKeyInfo;
        this.extensions = extensions;
        this.signatureValueItem = signatureValueItem;
        this.signature = signature;
    }

    /**
     * Parse a C509 certificate from its CBOR encoding.
     */
    public static C509Certificate getInstance(byte[] encoding)
        throws IOException
    {
        CBORDecoder in = new CBORDecoder(encoding);
        int count = in.readArrayHeader();
        if (count != 11)
        {
            throw new IOException("C509Certificate array must have 11 elements");
        }
        C509Certificate cert = parseFields(in);
        in.expectEnd();
        return cert;
    }

    /**
     * Assemble a certificate from an encoded TBSCertificate (see
     * {@link #createTBSCertificate}) and the newly created signature over it.
     *
     * @param tbsCertificate the encoding of the TBSCertificate CBOR sequence.
     * @param signature the signature value in its X.509 form (for ECDSA the DER
     *        SEQUENCE of the two INTEGERs, as produced by a ContentSigner).
     */
    public static C509Certificate create(byte[] tbsCertificate, byte[] signature)
        throws IOException
    {
        return create(tbsCertificate, signature, C509ConversionOptions.DEFAULT);
    }

    /**
     * Assemble a certificate from an encoded TBSCertificate and the newly created
     * signature over it, with the options controlling the ECDSA signature component
     * width.
     */
    public static C509Certificate create(byte[] tbsCertificate, byte[] signature, C509ConversionOptions options)
        throws IOException
    {
        CBORDecoder tbsIn = new CBORDecoder(tbsCertificate);
        Fields fields = parseTBSFields(tbsIn);
        tbsIn.expectEnd();
        byte[] signatureValueItem = C509SignatureValueCodec.encodeSignatureValue(fields.issuerSignatureAlgorithm,
            signature, options.getEcdsaSignatureValueWidth());
        return fields.build(signatureValueItem, signature);
    }

    private static C509Certificate parseFields(CBORDecoder in)
        throws IOException
    {
        Fields fields = parseTBSFields(in);
        byte[] signatureValueItem = in.readEncodedItem();
        CBORDecoder valueIn = new CBORDecoder(signatureValueItem);
        byte[] signature = C509SignatureValueCodec.decodeSignatureValue(fields.issuerSignatureAlgorithm, valueIn);
        valueIn.expectEnd();
        return fields.build(signatureValueItem, signature);
    }

    private static class Fields
    {
        int certificateType;
        byte[] serialNumber;
        C509AlgorithmIdentifier issuerSignatureAlgorithm;
        C509Name issuer;
        long notBefore;
        long notAfter;
        C509Name subject;
        C509AlgorithmIdentifier subjectPublicKeyAlgorithm;
        byte[] subjectPublicKeyItem;
        SubjectPublicKeyInfo subjectPublicKeyInfo;
        C509Extensions extensions;

        C509Certificate build(byte[] signatureValueItem, byte[] signature)
        {
            return new C509Certificate(certificateType, serialNumber, issuerSignatureAlgorithm, issuer,
                notBefore, notAfter, subject, subjectPublicKeyAlgorithm, subjectPublicKeyItem,
                subjectPublicKeyInfo, extensions, signatureValueItem, signature);
        }
    }

    private static Fields parseTBSFields(CBORDecoder in)
        throws IOException
    {
        Fields fields = new Fields();

        fields.certificateType = in.readInt();
        if (fields.certificateType != TYPE_NATIVE && fields.certificateType != TYPE_REENCODED_X509)
        {
            throw new IOException("unsupported c509CertificateType: " + fields.certificateType);
        }

        byte[] serialMagnitude = in.readByteString();
        if (serialMagnitude.length > 0 && serialMagnitude[0] == 0)
        {
            throw new IOException("C509 certificateSerialNumber with leading zero octet");
        }
        fields.serialNumber = serialMagnitude;

        fields.issuerSignatureAlgorithm = C509AlgorithmIdentifier.parseSignatureAlgorithm(in);

        if (in.nextIsNull())
        {
            in.readNull();
            fields.issuer = null;
        }
        else
        {
            fields.issuer = C509Name.parse(in);
        }

        fields.notBefore = in.readUnsignedInteger();
        if (in.nextIsNull())
        {
            in.readNull();
            fields.notAfter = NO_EXPIRATION_DATE;
        }
        else
        {
            fields.notAfter = in.readUnsignedInteger();
            if (fields.notAfter == NO_EXPIRATION_DATE)
            {
                throw new IOException("validityNotAfter of 99991231235959Z must be encoded as null");
            }
        }

        fields.subject = C509Name.parse(in);
        fields.subjectPublicKeyAlgorithm = C509AlgorithmIdentifier.parsePublicKeyAlgorithm(in);
        fields.subjectPublicKeyItem = in.readEncodedItem();
        fields.subjectPublicKeyInfo = C509PublicKeyCodec.decodeSubjectPublicKey(fields.subjectPublicKeyAlgorithm,
            fields.subjectPublicKeyItem);
        fields.extensions = C509Extensions.parse(in);

        return fields;
    }

    /**
     * Encode the TBSCertificate group for a certificate about to be signed. For a
     * natively signed certificate the returned encoding is exactly the byte string
     * the signature is computed over.
     *
     * @param certificateType {@link #TYPE_NATIVE} or {@link #TYPE_REENCODED_X509}.
     * @param serialNumber the certificate serial number, which must not be negative.
     * @param issuerSignatureAlgorithm the X.509 signature algorithm.
     * @param issuer the issuer name, or null when identical to the subject.
     * @param notBefore start of validity.
     * @param notAfter end of validity, null standing for no well-defined expiration.
     * @param subject the subject name.
     * @param subjectPublicKeyInfo the subject public key.
     * @param extensions the certificate extensions, or null for none.
     */
    public static byte[] createTBSCertificate(int certificateType, BigInteger serialNumber,
        AlgorithmIdentifier issuerSignatureAlgorithm, X500Name issuer, Date notBefore, Date notAfter,
        X500Name subject, SubjectPublicKeyInfo subjectPublicKeyInfo, Extensions extensions,
        C509ConversionOptions options)
        throws IOException
    {
        if (certificateType != TYPE_NATIVE && certificateType != TYPE_REENCODED_X509)
        {
            throw new IOException("unsupported c509CertificateType: " + certificateType);
        }
        if (serialNumber.signum() < 0)
        {
            throw new IOException("certificateSerialNumber must not be negative");
        }

        C509AlgorithmIdentifier sigAlg = C509AlgorithmIdentifier.forSignatureAlgorithm(issuerSignatureAlgorithm);
        C509AlgorithmIdentifier pkAlg = C509AlgorithmIdentifier.forPublicKeyAlgorithm(
            subjectPublicKeyInfo.getAlgorithm());

        C509Name subjectName = fromX500NameChecked(subject);
        C509Name issuerName = null;
        if (issuer != null && !issuer.equals(subject))
        {
            issuerName = fromX500NameChecked(issuer);
        }

        byte[] subjectPublicKeyItem = C509PublicKeyCodec.encodeSubjectPublicKey(pkAlg, subjectPublicKeyInfo,
            options.isPointCompression(), certificateType == TYPE_NATIVE);

        C509Extensions c509Extensions = C509Extensions.fromX509Extensions(extensions);
        if (certificateType == TYPE_NATIVE)
        {
            checkNativeExtensions(c509Extensions);
        }

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        CBOREncoder out = new CBOREncoder(bOut);
        out.writeInteger(certificateType);
        out.writeByteString(BigIntegers.asUnsignedByteArray(serialNumber));
        sigAlg.encodeTo(out);
        if (issuerName == null)
        {
            out.writeNull();
        }
        else
        {
            issuerName.encodeTo(out);
        }
        out.writeUnsignedInteger(toEpochSeconds(notBefore, "validityNotBefore"));
        if (notAfter == null)
        {
            out.writeNull();
        }
        else
        {
            long notAfterSeconds = toEpochSeconds(notAfter, "validityNotAfter");
            if (notAfterSeconds == NO_EXPIRATION_DATE)
            {
                out.writeNull();
            }
            else
            {
                out.writeUnsignedInteger(notAfterSeconds);
            }
        }
        subjectName.encodeTo(out);
        pkAlg.encodeTo(out);
        out.writeEncoded(subjectPublicKeyItem);
        c509Extensions.encodeTo(out);
        return bOut.toByteArray();
    }

    private static C509Name fromX500NameChecked(X500Name name)
        throws IOException
    {
        try
        {
            return C509Name.fromX500Name(name);
        }
        catch (IllegalArgumentException e)
        {
            throw Exceptions.ioException(e.getMessage(), e);
        }
    }

    /**
     * A natively signed certificate must use only specific CBOR encodings
     * (Section 3.7); a registered extension that fell back to the generic ~oid form
     * cannot be part of one.
     */
    private static void checkNativeExtensions(C509Extensions extensions)
        throws IOException
    {
        for (int i = 0; i != extensions.size(); i++)
        {
            C509Extension ext = extensions.getExtension(i);
            if (ext.getRegistryValue() == null && C509ExtensionType.getValue(ext.getExtnId()) != null)
            {
                throw new IOException("extension " + ext.getExtnId()
                    + " cannot use its specific CBOR encoding and so cannot appear in a natively signed certificate");
            }
        }
    }

    private static long toEpochSeconds(Date date, String field)
        throws IOException
    {
        long millis = date.getTime();
        if (millis % 1000 != 0)
        {
            throw new IOException(field + " must be a whole number of seconds");
        }
        long seconds = millis / 1000;
        if (seconds < 0)
        {
            throw new IOException(field + " must not be before 1970-01-01T00:00:00Z");
        }
        return seconds;
    }

    /**
     * Convert a DER-encoded X.509 v3 certificate to a CBOR re-encoded C509
     * certificate (type 3) using the default conversion options.
     */
    public static C509Certificate fromX509Certificate(byte[] derEncoding)
        throws IOException
    {
        return fromX509Certificate(parseX509(derEncoding), C509ConversionOptions.DEFAULT);
    }

    /**
     * Convert a DER-encoded X.509 v3 certificate to a CBOR re-encoded C509
     * certificate (type 3).
     * <p>
     * The conversion is gated on exact invertibility: after converting, the X.509
     * certificate is reconstructed and compared byte for byte with the input, and any
     * difference (a certificate that is not DER, or uses a construct the C509 profile
     * cannot carry, such as a multi-valued RDN) fails the conversion with an
     * IOException rather than producing a certificate whose copied signature could
     * never verify.
     */
    public static C509Certificate fromX509Certificate(Certificate x509Certificate, C509ConversionOptions options)
        throws IOException
    {
        try
        {
            return convertFromX509(x509Certificate, options);
        }
        catch (RuntimeException e)
        {
            // lazily decoded components of a malformed certificate surface unchecked
            // exceptions from their accessors; the conversion boundary reports them all
            // as conversion failures
            throw Exceptions.ioException(
                "X.509 certificate cannot be re-encoded as C509: " + e.getMessage(), e);
        }
    }

    private static C509Certificate convertFromX509(Certificate x509Certificate, C509ConversionOptions options)
        throws IOException
    {
        TBSCertificate tbs = x509Certificate.getTBSCertificate();

        if (tbs.getVersionNumber() != 3)
        {
            throw new IOException("only X.509 v3 certificates can be re-encoded as C509");
        }
        if (!x509Certificate.getSignatureAlgorithm().equals(tbs.getSignature()))
        {
            throw new IOException("signatureAlgorithm does not match the TBSCertificate signature field");
        }
        if (tbs.getIssuerUniqueId() != null || tbs.getSubjectUniqueId() != null)
        {
            throw new IOException("issuerUniqueID and subjectUniqueID are not supported by C509");
        }
        if (tbs.getSerialNumber().getValue().signum() < 0)
        {
            throw new IOException("certificateSerialNumber must not be negative");
        }
        if (x509Certificate.getSignature().getPadBits() != 0)
        {
            throw new IOException("C509 signatureValue BIT STRING must have zero unused bits");
        }

        byte[] tbsEncoding = createTBSCertificate(TYPE_REENCODED_X509, tbs.getSerialNumber().getValue(),
            tbs.getSignature(), tbs.getIssuer(), tbs.getStartDate().getDate(), tbs.getEndDate().getDate(),
            tbs.getSubject(), tbs.getSubjectPublicKeyInfo(), tbs.getExtensions(), options);

        C509Certificate c509 = create(tbsEncoding, x509Certificate.getSignature().getBytes(), options);

        // the invertibility gate: re-encoding must reproduce the input exactly, or the
        // copied signature could never be verified again
        byte[] rebuilt = c509.toX509Certificate().getEncoded(ASN1Encoding.DER);
        byte[] original = x509Certificate.getEncoded(ASN1Encoding.DER);
        if (!Arrays.areEqual(rebuilt, original))
        {
            throw new IOException(
                "X.509 certificate cannot be losslessly re-encoded as C509 - it is not DER or uses a construct outside the C509 profile");
        }
        return c509;
    }

    private static Certificate parseX509(byte[] derEncoding)
        throws IOException
    {
        try
        {
            return Certificate.getInstance(ASN1Sequence.getInstance(derEncoding));
        }
        catch (RuntimeException e)
        {
            throw Exceptions.ioException("malformed X.509 certificate", e);
        }
    }

    /**
     * Reconstruct the X.509 certificate a CBOR re-encoded C509 certificate stands
     * for. For a type 3 certificate the result is byte for byte the DER certificate
     * that was re-encoded, and its signature verifies in the usual X.509 way.
     *
     * @throws IllegalStateException if this is a natively signed certificate - its
     *         signature only covers the CBOR encoding, so no verifiable X.509 view of
     *         it exists.
     */
    public Certificate toX509Certificate()
    {
        if (certificateType != TYPE_REENCODED_X509)
        {
            throw new IllegalStateException(
                "a natively signed C509 certificate has no X.509 form - its signature covers the CBOR encoding");
        }
        V3TBSCertificateGenerator tbsGen = new V3TBSCertificateGenerator();
        tbsGen.setSerialNumber(new ASN1Integer(getSerialNumber()));
        tbsGen.setSignature(issuerSignatureAlgorithm.toX509AlgorithmIdentifier());
        X500Name issuerName = issuer == null ? subject.toX500Name() : issuer.toX500Name();
        tbsGen.setIssuer(issuerName);
        tbsGen.setStartDate(new Time(new Date(notBefore * 1000), Locale.US));
        tbsGen.setEndDate(new Time(new Date(notAfter * 1000), Locale.US));
        tbsGen.setSubject(subject.toX500Name());
        tbsGen.setSubjectPublicKeyInfo(subjectPublicKeyInfo);
        Extensions x509Extensions = extensions.toX509Extensions();
        if (x509Extensions != null)
        {
            tbsGen.setExtensions(x509Extensions);
        }
        TBSCertificate tbs = tbsGen.generateTBSCertificate();
        return Certificate.getInstance(new DERSequence(new ASN1Encodable[]
            { tbs, issuerSignatureAlgorithm.toX509AlgorithmIdentifier(), new DERBitString(signature) }));
    }

    /**
     * Return the complete CBOR encoding of this certificate.
     */
    public byte[] getEncoded()
        throws IOException
    {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        CBOREncoder out = new CBOREncoder(bOut);
        out.writeArrayHeader(11);
        encodeTBSTo(out);
        out.writeEncoded(signatureValueItem);
        return bOut.toByteArray();
    }

    /**
     * Return the encoding of the TBSCertificate group as a CBOR sequence - for a
     * natively signed certificate, the exact bytes the signature covers.
     */
    public byte[] getTBSCertificateEncoded()
        throws IOException
    {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        encodeTBSTo(new CBOREncoder(bOut));
        return bOut.toByteArray();
    }

    private void encodeTBSTo(CBOREncoder out)
        throws IOException
    {
        out.writeInteger(certificateType);
        out.writeByteString(serialNumber);
        issuerSignatureAlgorithm.encodeTo(out);
        if (issuer == null)
        {
            out.writeNull();
        }
        else
        {
            issuer.encodeTo(out);
        }
        out.writeUnsignedInteger(notBefore);
        if (notAfter == NO_EXPIRATION_DATE)
        {
            out.writeNull();
        }
        else
        {
            out.writeUnsignedInteger(notAfter);
        }
        subject.encodeTo(out);
        subjectPublicKeyAlgorithm.encodeTo(out);
        out.writeEncoded(subjectPublicKeyItem);
        extensions.encodeTo(out);
    }

    /**
     * Return the certificate type ({@link #TYPE_NATIVE} or {@link #TYPE_REENCODED_X509}).
     */
    public int getCertificateType()
    {
        return certificateType;
    }

    /**
     * Return the certificate serial number.
     */
    public BigInteger getSerialNumber()
    {
        return new BigInteger(1, serialNumber);
    }

    /**
     * Return the issuer signature algorithm.
     */
    public C509AlgorithmIdentifier getIssuerSignatureAlgorithm()
    {
        return issuerSignatureAlgorithm;
    }

    /**
     * Return the issuer name. In the C509 encoding an issuer identical to the subject
     * is carried as null; this accessor resolves that back to the subject name.
     */
    public X500Name getIssuer()
    {
        return issuer == null ? subject.toX500Name() : issuer.toX500Name();
    }

    /**
     * Return true if the issuer field is carried as null, standing for an issuer
     * identical to the subject (Section 3.1.4).
     */
    public boolean isSelfIssued()
    {
        return issuer == null;
    }

    /**
     * Return the start of validity, in POSIX seconds.
     */
    public long getNotBefore()
    {
        return notBefore;
    }

    /**
     * Return the end of validity, in POSIX seconds; {@link #NO_EXPIRATION_DATE}
     * stands for no well-defined expiration date.
     */
    public long getNotAfter()
    {
        return notAfter;
    }

    /**
     * Return the subject name.
     */
    public X500Name getSubject()
    {
        return subject.toX500Name();
    }

    /**
     * Return the subject public key algorithm.
     */
    public C509AlgorithmIdentifier getSubjectPublicKeyAlgorithm()
    {
        return subjectPublicKeyAlgorithm;
    }

    /**
     * Return the subject public key. For a re-encoded certificate whose point was
     * compressed with the 0xfe/0xfd markers, the point has been expanded back to the
     * uncompressed form the DER encoding held.
     */
    public SubjectPublicKeyInfo getSubjectPublicKeyInfo()
    {
        return subjectPublicKeyInfo;
    }

    /**
     * Return the extensions.
     */
    public C509Extensions getExtensions()
    {
        return extensions;
    }

    /**
     * Return the signature value in its X.509 form: for an ECDSA style algorithm the
     * DER SEQUENCE of the two INTEGERs, otherwise the BIT STRING value field
     * unchanged. This is the form a ContentVerifier checks.
     */
    public byte[] getSignature()
    {
        return Arrays.clone(signature);
    }

    public boolean equals(Object o)
    {
        if (o == this)
        {
            return true;
        }
        if (!(o instanceof C509Certificate))
        {
            return false;
        }
        try
        {
            return Arrays.areEqual(getEncoded(), ((C509Certificate)o).getEncoded());
        }
        catch (IOException e)
        {
            return false;
        }
    }

    public int hashCode()
    {
        try
        {
            return Arrays.hashCode(getEncoded());
        }
        catch (IOException e)
        {
            return 0;
        }
    }
}
