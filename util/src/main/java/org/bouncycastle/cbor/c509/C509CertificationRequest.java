package org.bouncycastle.cbor.c509;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1PrintableString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1UTF8String;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.pkcs.CertificationRequestInfo;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509AttributeIdentifiers;
import org.bouncycastle.cbor.CBORDecoder;
import org.bouncycastle.cbor.CBOREncoder;
import org.bouncycastle.cbor.CBORType;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Exceptions;
import org.bouncycastle.util.Integers;

/**
 * A C509 certification request (Section 4 of draft-ietf-cose-cbor-encoded-cert-20):
 * <pre>
 * C509CertificationRequest = [ TBSCertificationRequest, subjectSignatureValue: any ]
 * </pre>
 * where the six elements of the TBSCertificationRequest group are inlined into the
 * array. As with certificates, type 2 is natively signed (the signature covers the
 * TBSCertificationRequest CBOR sequence) and type 3 is an invertible re-encoding of a
 * DER RFC 2986 certification request whose signature is copied and remains verifiable
 * over the reconstructed DER.
 */
public class C509CertificationRequest
{
    /** Natively signed C509 certification request (c509CertificationRequestType = 2). */
    public static final int TYPE_NATIVE = 2;
    /** CBOR re-encoding of an RFC 2986 certification request (c509CertificationRequestType = 3). */
    public static final int TYPE_REENCODED_PKCS10 = 3;

    /** CBOR tag 121 marking a challengePassword carried as a PrintableString (Section 4.3.2). */
    private static final long TAG_PRINTABLE_STRING = 121;

    private static final ASN1ObjectIdentifier pkcs_9_at_extensionRequest =
        PKCSObjectIdentifiers.pkcs_9_at_extensionRequest;
    private static final ASN1ObjectIdentifier pkcs_9_at_challengePassword =
        PKCSObjectIdentifiers.pkcs_9_at_challengePassword;
    private static final ASN1ObjectIdentifier id_aa_privateKeyPossessionStatement =
        X509AttributeIdentifiers.id_at_statementOfPossession;

    private final int requestType;
    private final C509AlgorithmIdentifier subjectSignatureAlgorithm;
    private final C509Name subject;
    private final C509AlgorithmIdentifier subjectPublicKeyAlgorithm;
    private final byte[] subjectPublicKeyItem;
    private final SubjectPublicKeyInfo subjectPublicKeyInfo;
    private final C509Attribute[] attributes;
    private final byte[] signatureValueItem;
    private final byte[] signature;

    private C509CertificationRequest(int requestType, C509AlgorithmIdentifier subjectSignatureAlgorithm,
        C509Name subject, C509AlgorithmIdentifier subjectPublicKeyAlgorithm, byte[] subjectPublicKeyItem,
        SubjectPublicKeyInfo subjectPublicKeyInfo, C509Attribute[] attributes, byte[] signatureValueItem,
        byte[] signature)
    {
        this.requestType = requestType;
        this.subjectSignatureAlgorithm = subjectSignatureAlgorithm;
        this.subject = subject;
        this.subjectPublicKeyAlgorithm = subjectPublicKeyAlgorithm;
        this.subjectPublicKeyItem = subjectPublicKeyItem;
        this.subjectPublicKeyInfo = subjectPublicKeyInfo;
        this.attributes = attributes;
        this.signatureValueItem = signatureValueItem;
        this.signature = signature;
    }

    /**
     * Parse a C509 certification request from its CBOR encoding.
     */
    public static C509CertificationRequest getInstance(byte[] encoding)
        throws IOException
    {
        CBORDecoder in = new CBORDecoder(encoding);
        int count = in.readArrayHeader();
        if (count != 7)
        {
            throw new IOException("C509CertificationRequest array must have 7 elements");
        }
        Fields fields = parseTBSFields(in);
        byte[] signatureValueItem = in.readEncodedItem();
        CBORDecoder valueIn = new CBORDecoder(signatureValueItem);
        byte[] signature = C509SignatureValueCodec.decodeSignatureValue(fields.subjectSignatureAlgorithm, valueIn);
        valueIn.expectEnd();
        in.expectEnd();
        return fields.build(signatureValueItem, signature);
    }

    /**
     * Assemble a certification request from an encoded TBSCertificationRequest (see
     * {@link #createTBSCertificationRequest}) and the newly created signature over it.
     */
    public static C509CertificationRequest create(byte[] tbsCertificationRequest, byte[] signature)
        throws IOException
    {
        return create(tbsCertificationRequest, signature, C509ConversionOptions.DEFAULT);
    }

    /**
     * Assemble a certification request from an encoded TBSCertificationRequest and
     * the newly created signature over it, with the options controlling the ECDSA
     * signature component width.
     */
    public static C509CertificationRequest create(byte[] tbsCertificationRequest, byte[] signature,
        C509ConversionOptions options)
        throws IOException
    {
        CBORDecoder tbsIn = new CBORDecoder(tbsCertificationRequest);
        Fields fields = parseTBSFields(tbsIn);
        tbsIn.expectEnd();
        byte[] signatureValueItem = C509SignatureValueCodec.encodeSignatureValue(fields.subjectSignatureAlgorithm,
            signature, options.getEcdsaSignatureValueWidth());
        return fields.build(signatureValueItem, signature);
    }

    private static class Fields
    {
        int requestType;
        C509AlgorithmIdentifier subjectSignatureAlgorithm;
        C509Name subject;
        C509AlgorithmIdentifier subjectPublicKeyAlgorithm;
        byte[] subjectPublicKeyItem;
        SubjectPublicKeyInfo subjectPublicKeyInfo;
        C509Attribute[] attributes;

        C509CertificationRequest build(byte[] signatureValueItem, byte[] signature)
        {
            return new C509CertificationRequest(requestType, subjectSignatureAlgorithm, subject,
                subjectPublicKeyAlgorithm, subjectPublicKeyItem, subjectPublicKeyInfo, attributes,
                signatureValueItem, signature);
        }
    }

    private static Fields parseTBSFields(CBORDecoder in)
        throws IOException
    {
        Fields fields = new Fields();

        fields.requestType = in.readInt();
        if (fields.requestType != TYPE_NATIVE && fields.requestType != TYPE_REENCODED_PKCS10)
        {
            throw new IOException("unsupported c509CertificationRequestType: " + fields.requestType);
        }
        fields.subjectSignatureAlgorithm = C509AlgorithmIdentifier.parseSignatureAlgorithm(in);
        fields.subject = C509Name.parse(in);
        fields.subjectPublicKeyAlgorithm = C509AlgorithmIdentifier.parsePublicKeyAlgorithm(in);
        fields.subjectPublicKeyItem = in.readEncodedItem();
        fields.subjectPublicKeyInfo = C509PublicKeyCodec.decodeSubjectPublicKey(fields.subjectPublicKeyAlgorithm,
            fields.subjectPublicKeyItem);

        int attributeCount = in.readArrayHeader();
        if ((attributeCount & 1) != 0)
        {
            throw new IOException("C509 CRAttributes array must hold (attributeType, attributeValue) pairs");
        }
        fields.attributes = new C509Attribute[attributeCount / 2];
        for (int i = 0; i != fields.attributes.length; i++)
        {
            fields.attributes[i] = parseAttribute(in);
        }
        return fields;
    }

    private static C509Attribute parseAttribute(CBORDecoder in)
        throws IOException
    {
        int major = in.peekMajorType();
        if (major == CBORType.UNSIGNED_INTEGER || major == CBORType.NEGATIVE_INTEGER)
        {
            int registryValue = in.readInt();
            ASN1ObjectIdentifier oid;
            byte[] value;
            switch (registryValue)
            {
            case C509Attribute.EXTENSION_REQUEST:
            {
                oid = pkcs_9_at_extensionRequest;
                // the value has type Extensions (Section 4.3.1); validate it fully
                value = in.readEncodedItem();
                CBORDecoder valueIn = new CBORDecoder(value);
                C509Extensions.parse(valueIn);
                valueIn.expectEnd();
                break;
            }
            case C509Attribute.CHALLENGE_PASSWORD:
            {
                oid = pkcs_9_at_challengePassword;
                value = in.readEncodedItem();
                CBORDecoder valueIn = new CBORDecoder(value);
                readChallengePassword(valueIn);
                valueIn.expectEnd();
                break;
            }
            case C509Attribute.PRIVATE_KEY_POSSESSION_STATEMENT:
            {
                oid = id_aa_privateKeyPossessionStatement;
                // carried structurally validated but uninterpreted; it embeds a
                // C509CertData and has no direct DER reconstruction
                value = in.readEncodedItem();
                break;
            }
            default:
                throw new IOException("unknown C509 CR attribute value: " + registryValue);
            }
            return new C509Attribute(Integers.valueOf(registryValue), oid, value);
        }

        if (major == CBORType.BYTE_STRING)
        {
            ASN1ObjectIdentifier oid = C509Oids.fromContents(in.readByteString());
            byte[] value = in.readEncodedItem();
            CBORDecoder valueIn = new CBORDecoder(value);
            byte[] derValue = valueIn.readByteString();
            valueIn.expectEnd();
            try
            {
                ASN1Primitive.fromByteArray(derValue);
            }
            catch (RuntimeException e)
            {
                throw new IOException("malformed C509 CR attribute value");
            }
            return new C509Attribute(null, oid, value);
        }

        throw new IOException("C509 CR attributeType expected, found major type " + major);
    }

    private static String readChallengePassword(CBORDecoder in)
        throws IOException
    {
        if (in.peekMajorType() == CBORType.TAG)
        {
            long tag = in.readTag();
            if (tag != TAG_PRINTABLE_STRING)
            {
                throw new IOException("C509 ChallengePassword with unsupported tag " + tag);
            }
            return in.readTextString();
        }
        return in.readTextString();
    }

    /**
     * Encode the TBSCertificationRequest group for a request about to be signed. For
     * a natively signed request the returned encoding is exactly the byte string the
     * signature is computed over.
     *
     * @param requestType {@link #TYPE_NATIVE} or {@link #TYPE_REENCODED_PKCS10}.
     * @param subjectSignatureAlgorithm the X.509 signature (or RFC 6955
     *        proof-of-possession) algorithm.
     * @param subject the subject name.
     * @param subjectPublicKeyInfo the subject public key.
     * @param extensionRequest extensions requested of the CA (RFC 2985
     *        extensionRequest), or null for none.
     * @param challengePassword a challenge password (RFC 2985), or null for none.
     */
    public static byte[] createTBSCertificationRequest(int requestType,
        AlgorithmIdentifier subjectSignatureAlgorithm, X500Name subject,
        SubjectPublicKeyInfo subjectPublicKeyInfo, Extensions extensionRequest, String challengePassword,
        C509ConversionOptions options)
        throws IOException
    {
        if (requestType != TYPE_NATIVE && requestType != TYPE_REENCODED_PKCS10)
        {
            throw new IOException("unsupported c509CertificationRequestType: " + requestType);
        }

        C509AlgorithmIdentifier sigAlg = C509AlgorithmIdentifier.forSignatureAlgorithm(subjectSignatureAlgorithm);
        C509AlgorithmIdentifier pkAlg = C509AlgorithmIdentifier.forPublicKeyAlgorithm(
            subjectPublicKeyInfo.getAlgorithm());

        C509Name subjectName;
        try
        {
            subjectName = C509Name.fromX500Name(subject);
        }
        catch (IllegalArgumentException e)
        {
            throw Exceptions.ioException(e.getMessage(), e);
        }

        byte[] subjectPublicKeyItem = C509PublicKeyCodec.encodeSubjectPublicKey(pkAlg, subjectPublicKeyInfo,
            options.isPointCompression(), requestType == TYPE_NATIVE);

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        CBOREncoder out = new CBOREncoder(bOut);
        out.writeInteger(requestType);
        sigAlg.encodeTo(out);
        subjectName.encodeTo(out);
        pkAlg.encodeTo(out);
        out.writeEncoded(subjectPublicKeyItem);

        int attributeCount = (extensionRequest != null ? 1 : 0) + (challengePassword != null ? 1 : 0);
        out.writeArrayHeader(2 * attributeCount);
        if (extensionRequest != null)
        {
            C509Extensions c509Extensions = C509Extensions.fromX509Extensions(extensionRequest);
            if (requestType == TYPE_NATIVE)
            {
                for (int i = 0; i != c509Extensions.size(); i++)
                {
                    C509Extension ext = c509Extensions.getExtension(i);
                    if (ext.getRegistryValue() == null && C509ExtensionType.getValue(ext.getExtnId()) != null)
                    {
                        throw new IOException("extension " + ext.getExtnId()
                            + " cannot use its specific CBOR encoding and so cannot appear in a natively signed request");
                    }
                }
            }
            out.writeInteger(C509Attribute.EXTENSION_REQUEST);
            c509Extensions.encodeTo(out);
        }
        if (challengePassword != null)
        {
            out.writeInteger(C509Attribute.CHALLENGE_PASSWORD);
            out.writeTextString(challengePassword);
        }
        return bOut.toByteArray();
    }

    /**
     * Convert a DER-encoded RFC 2986 certification request to a CBOR re-encoded C509
     * certification request (type 3) using the default conversion options.
     */
    public static C509CertificationRequest fromCertificationRequest(byte[] derEncoding)
        throws IOException
    {
        try
        {
            return fromCertificationRequest(
                CertificationRequest.getInstance(ASN1Sequence.getInstance(derEncoding)),
                C509ConversionOptions.DEFAULT);
        }
        catch (RuntimeException e)
        {
            throw Exceptions.ioException("malformed certification request", e);
        }
    }

    /**
     * Convert a DER-encoded RFC 2986 certification request to a CBOR re-encoded C509
     * certification request (type 3). As with certificates the conversion is gated on
     * exact invertibility - if re-encoding the result does not reproduce the input
     * DER byte for byte, the conversion is refused.
     */
    public static C509CertificationRequest fromCertificationRequest(CertificationRequest request,
        C509ConversionOptions options)
        throws IOException
    {
        try
        {
            return convertFromCertificationRequest(request, options);
        }
        catch (RuntimeException e)
        {
            throw Exceptions.ioException(
                "certification request cannot be re-encoded as C509: " + e.getMessage(), e);
        }
    }

    private static C509CertificationRequest convertFromCertificationRequest(CertificationRequest request,
        C509ConversionOptions options)
        throws IOException
    {
        CertificationRequestInfo info = request.getCertificationRequestInfo();
        if (!info.getVersion().hasValue(0))
        {
            throw new IOException("only version 1 certification requests can be re-encoded as C509");
        }
        if (request.getSignature().getPadBits() != 0)
        {
            throw new IOException("C509 subjectSignatureValue BIT STRING must have zero unused bits");
        }

        Extensions extensionRequest = null;
        String challengePassword = null;
        boolean challengePasswordPrintable = false;
        ASN1Set attributeSet = info.getAttributes();
        ByteArrayOutputStream attrOut = new ByteArrayOutputStream();
        CBOREncoder attrEnc = new CBOREncoder(attrOut);
        int attributeCount = attributeSet == null ? 0 : attributeSet.size();
        attrEnc.writeArrayHeader(2 * attributeCount);
        for (int i = 0; i != attributeCount; i++)
        {
            Attribute attribute = Attribute.getInstance(attributeSet.getObjectAt(i));
            ASN1Set values = attribute.getAttrValues();
            C509Extensions extensionRequestValue = null;
            if (pkcs_9_at_extensionRequest.equals(attribute.getAttrType()) && values.size() == 1)
            {
                try
                {
                    extensionRequestValue =
                        C509Extensions.fromX509Extensions(Extensions.getInstance(values.getObjectAt(0)));
                }
                catch (RuntimeException e)
                {
                    // not a well-formed Extensions value; carry it in the generic form
                }
            }
            if (extensionRequestValue != null)
            {
                attrEnc.writeInteger(C509Attribute.EXTENSION_REQUEST);
                extensionRequestValue.encodeTo(attrEnc);
            }
            else if (pkcs_9_at_challengePassword.equals(attribute.getAttrType()) && values.size() == 1
                && (values.getObjectAt(0) instanceof ASN1UTF8String
                    || values.getObjectAt(0) instanceof ASN1PrintableString))
            {
                attrEnc.writeInteger(C509Attribute.CHALLENGE_PASSWORD);
                if (values.getObjectAt(0) instanceof ASN1PrintableString)
                {
                    attrEnc.writeTag(TAG_PRINTABLE_STRING);
                    attrEnc.writeTextString(((ASN1PrintableString)values.getObjectAt(0)).getString());
                }
                else
                {
                    attrEnc.writeTextString(((ASN1UTF8String)values.getObjectAt(0)).getString());
                }
            }
            else if (values.size() == 1)
            {
                attrEnc.writeByteString(C509Oids.toContents(attribute.getAttrType()));
                attrEnc.writeByteString(values.getObjectAt(0).toASN1Primitive().getEncoded(ASN1Encoding.DER));
            }
            else
            {
                throw new IOException("certification request attribute with " + values.size()
                    + " values cannot be re-encoded as C509");
            }
        }

        C509AlgorithmIdentifier sigAlg =
            C509AlgorithmIdentifier.forSignatureAlgorithm(request.getSignatureAlgorithm());
        C509AlgorithmIdentifier pkAlg = C509AlgorithmIdentifier.forPublicKeyAlgorithm(
            info.getSubjectPublicKeyInfo().getAlgorithm());
        C509Name subjectName;
        try
        {
            subjectName = C509Name.fromX500Name(X500Name.getInstance(info.getSubject()));
        }
        catch (IllegalArgumentException e)
        {
            throw Exceptions.ioException(e.getMessage(), e);
        }
        byte[] subjectPublicKeyItem = C509PublicKeyCodec.encodeSubjectPublicKey(pkAlg,
            info.getSubjectPublicKeyInfo(), options.isPointCompression(), false);

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        CBOREncoder out = new CBOREncoder(bOut);
        out.writeInteger(TYPE_REENCODED_PKCS10);
        sigAlg.encodeTo(out);
        subjectName.encodeTo(out);
        pkAlg.encodeTo(out);
        out.writeEncoded(subjectPublicKeyItem);
        out.writeEncoded(attrOut.toByteArray());

        C509CertificationRequest c509 = create(bOut.toByteArray(), request.getSignature().getBytes(), options);

        byte[] rebuilt = c509.toCertificationRequest().getEncoded(ASN1Encoding.DER);
        byte[] original = request.getEncoded(ASN1Encoding.DER);
        if (!Arrays.areEqual(rebuilt, original))
        {
            throw new IOException(
                "certification request cannot be losslessly re-encoded as C509 - it is not DER or uses a construct outside the C509 profile");
        }
        return c509;
    }

    /**
     * Reconstruct the RFC 2986 certification request a CBOR re-encoded C509
     * certification request stands for.
     *
     * @throws IllegalStateException if this is a natively signed request.
     * @throws IOException if an attribute (such as a privateKeyPossessionStatement,
     *         which embeds C509 structures) has no DER reconstruction.
     */
    public CertificationRequest toCertificationRequest()
        throws IOException
    {
        if (requestType != TYPE_REENCODED_PKCS10)
        {
            throw new IllegalStateException(
                "a natively signed C509 certification request has no RFC 2986 form - its signature covers the CBOR encoding");
        }
        ASN1Encodable[] attributeElements = new ASN1Encodable[attributes.length];
        for (int i = 0; i != attributes.length; i++)
        {
            attributeElements[i] = toPKCS10Attribute(attributes[i]);
        }
        CertificationRequestInfo info = new CertificationRequestInfo(subject.toX500Name(), subjectPublicKeyInfo,
            new DERSet(attributeElements));
        return new CertificationRequest(info, subjectSignatureAlgorithm.toX509AlgorithmIdentifier(),
            new DERBitString(signature));
    }

    private static Attribute toPKCS10Attribute(C509Attribute attribute)
        throws IOException
    {
        Integer registryValue = attribute.getRegistryValue();
        CBORDecoder valueIn = new CBORDecoder(attribute.getValueEncoding());
        if (registryValue == null)
        {
            byte[] derValue = valueIn.readByteString();
            valueIn.expectEnd();
            try
            {
                return new Attribute(attribute.getAttrType(), new DERSet(ASN1Primitive.fromByteArray(derValue)));
            }
            catch (RuntimeException e)
            {
                throw new IOException("malformed C509 CR attribute value");
            }
        }
        switch (registryValue.intValue())
        {
        case C509Attribute.EXTENSION_REQUEST:
        {
            C509Extensions extensions = C509Extensions.parse(valueIn);
            valueIn.expectEnd();
            Extensions x509Extensions = extensions.toX509Extensions();
            if (x509Extensions == null)
            {
                x509Extensions = new Extensions(new org.bouncycastle.asn1.x509.Extension[0]);
            }
            return new Attribute(attribute.getAttrType(), new DERSet(x509Extensions));
        }
        case C509Attribute.CHALLENGE_PASSWORD:
        {
            boolean printable = valueIn.peekMajorType() == CBORType.TAG;
            String password = readChallengePassword(valueIn);
            valueIn.expectEnd();
            return new Attribute(attribute.getAttrType(), new DERSet(
                printable ? (ASN1Encodable)new DERPrintableString(password) : new DERUTF8String(password)));
        }
        default:
            throw new IOException("C509 CR attribute " + registryValue
                + " has no RFC 2986 reconstruction");
        }
    }

    /**
     * Return the complete CBOR encoding of this certification request.
     */
    public byte[] getEncoded()
        throws IOException
    {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        CBOREncoder out = new CBOREncoder(bOut);
        out.writeArrayHeader(7);
        encodeTBSTo(out);
        out.writeEncoded(signatureValueItem);
        return bOut.toByteArray();
    }

    /**
     * Return the encoding of the TBSCertificationRequest group as a CBOR sequence -
     * for a natively signed request, the exact bytes the signature covers.
     */
    public byte[] getTBSCertificationRequestEncoded()
        throws IOException
    {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        encodeTBSTo(new CBOREncoder(bOut));
        return bOut.toByteArray();
    }

    private void encodeTBSTo(CBOREncoder out)
        throws IOException
    {
        out.writeInteger(requestType);
        subjectSignatureAlgorithm.encodeTo(out);
        subject.encodeTo(out);
        subjectPublicKeyAlgorithm.encodeTo(out);
        out.writeEncoded(subjectPublicKeyItem);
        out.writeArrayHeader(2 * attributes.length);
        for (int i = 0; i != attributes.length; i++)
        {
            C509Attribute attribute = attributes[i];
            if (attribute.getRegistryValue() != null)
            {
                out.writeInteger(attribute.getRegistryValue().intValue());
            }
            else
            {
                out.writeByteString(C509Oids.toContents(attribute.getAttrType()));
            }
            out.writeEncoded(attribute.getValueEncoding());
        }
    }

    /**
     * Return the request type ({@link #TYPE_NATIVE} or {@link #TYPE_REENCODED_PKCS10}).
     */
    public int getRequestType()
    {
        return requestType;
    }

    /**
     * Return the subject signature algorithm.
     */
    public C509AlgorithmIdentifier getSubjectSignatureAlgorithm()
    {
        return subjectSignatureAlgorithm;
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
     * Return the subject public key.
     */
    public SubjectPublicKeyInfo getSubjectPublicKeyInfo()
    {
        return subjectPublicKeyInfo;
    }

    /**
     * Return the request attributes.
     */
    public C509Attribute[] getAttributes()
    {
        C509Attribute[] result = new C509Attribute[attributes.length];
        System.arraycopy(attributes, 0, result, 0, attributes.length);
        return result;
    }

    /**
     * Return the signature value in its X.509 form: for an ECDSA style algorithm the
     * DER SEQUENCE of the two INTEGERs, otherwise the BIT STRING value field
     * unchanged.
     */
    public byte[] getSignature()
    {
        return Arrays.clone(signature);
    }
}
