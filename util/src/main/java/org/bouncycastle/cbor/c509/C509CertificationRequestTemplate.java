package org.bouncycastle.cbor.c509;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.cbor.CBORDecoder;
import org.bouncycastle.cbor.CBOREncoder;
import org.bouncycastle.cbor.CBORType;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Integers;

/**
 * A C509 certification request template (Section 4.4 of
 * draft-ietf-cose-cbor-encoded-cert-20), returned by an EST server in response to a
 * GET /csrattrs request to tell the client what its certification request should
 * contain:
 * <pre>
 * C509CertificationRequestTemplate = [
 *    c509CertificationRequestTemplateType: int,
 *    c509CertificationRequestType: [+ int] / undefined,
 *    subjectSignatureAlgorithm: [+ AlgorithmIdentifier] / undefined,
 *    subject: NameTemplate / undefined,
 *    subjectPublicKeyAlgorithm: [+ AlgorithmIdentifier] / undefined,
 *    subjectPublicKey: undefined,
 *    extensionsRequest: ExtensionsTemplate / undefined,
 * ]
 * </pre>
 * The CBOR simple value undefined marks the fields the client is expected to fill
 * in - represented here as null returns from the accessors.
 */
public class C509CertificationRequestTemplate
{
    /** Simple C509 Certification Request Template (Section 8.5). */
    public static final int TYPE_SIMPLE = 0;

    /**
     * An RDNAttributeTemplate group (Section 4.4): an attribute type with its minimum
     * and maximum number of occurrences and an optional prescribed value. A null
     * value encoding stands for the CBOR undefined - the client provides the value.
     */
    public static class RDNAttributeTemplate
    {
        private final Integer registryValue;
        private final ASN1ObjectIdentifier oid;
        private final long minOccurs;
        private final long maxOccurs;
        private final byte[] valueEncoding;

        public RDNAttributeTemplate(int registryValue, long minOccurs, long maxOccurs, byte[] valueEncoding)
        {
            this(Integers.valueOf(registryValue), null, minOccurs, maxOccurs, valueEncoding);
        }

        public RDNAttributeTemplate(ASN1ObjectIdentifier oid, long minOccurs, long maxOccurs, byte[] valueEncoding)
        {
            this(null, oid, minOccurs, maxOccurs, valueEncoding);
        }

        private RDNAttributeTemplate(Integer registryValue, ASN1ObjectIdentifier oid, long minOccurs,
            long maxOccurs, byte[] valueEncoding)
        {
            if (maxOccurs < minOccurs || maxOccurs < 1)
            {
                throw new IllegalArgumentException(
                    "maxOccurs must be positive and not less than minOccurs");
            }
            this.registryValue = registryValue;
            this.oid = oid;
            this.minOccurs = minOccurs;
            this.maxOccurs = maxOccurs;
            this.valueEncoding = valueEncoding;
        }

        /** Return the registered attribute value, or null for the ~oid form. */
        public Integer getRegistryValue()
        {
            return registryValue;
        }

        /** Return the attribute type OID for the ~oid form, or null for the int form. */
        public ASN1ObjectIdentifier getAttrType()
        {
            return oid;
        }

        public long getMinOccurs()
        {
            return minOccurs;
        }

        public long getMaxOccurs()
        {
            return maxOccurs;
        }

        /**
         * Return the CBOR encoding of the prescribed attribute value, or null when
         * the template leaves it undefined for the client to fill in.
         */
        public byte[] getValueEncoding()
        {
            return valueEncoding == null ? null : Arrays.clone(valueEncoding);
        }
    }

    /**
     * An ExtensionTemplate group (Section 4.4): an extension with an "optional" flag
     * and a prescribed or partial value. A null value encoding stands for the CBOR
     * undefined.
     */
    public static class ExtensionTemplate
    {
        private final Integer registryValue;
        private final ASN1ObjectIdentifier oid;
        private final boolean optional;
        private final byte[] valueEncoding;

        public ExtensionTemplate(int registryValue, boolean optional, byte[] valueEncoding)
        {
            this.registryValue = Integers.valueOf(registryValue);
            this.oid = null;
            this.optional = optional;
            this.valueEncoding = valueEncoding;
        }

        public ExtensionTemplate(ASN1ObjectIdentifier oid, boolean optional, byte[] valueEncoding)
        {
            this.registryValue = null;
            this.oid = oid;
            this.optional = optional;
            this.valueEncoding = valueEncoding;
        }

        /** Return the registered extension value, or null for the ~oid form. */
        public Integer getRegistryValue()
        {
            return registryValue;
        }

        /** Return the extension OID for the ~oid form, or null for the int form. */
        public ASN1ObjectIdentifier getExtnId()
        {
            return oid;
        }

        public boolean isOptional()
        {
            return optional;
        }

        /**
         * Return the CBOR encoding of the prescribed extension value, or null when
         * the template leaves it undefined.
         */
        public byte[] getValueEncoding()
        {
            return valueEncoding == null ? null : Arrays.clone(valueEncoding);
        }
    }

    private final int templateType;
    private final int[] requestTypes;
    private final C509AlgorithmIdentifier[] signatureAlgorithms;
    private final RDNAttributeTemplate[] subjectTemplate;
    private final C509AlgorithmIdentifier[] publicKeyAlgorithms;
    private final ExtensionTemplate[] extensionsTemplate;

    /**
     * Base constructor. Null array arguments stand for the CBOR undefined - fields
     * the client is expected to provide.
     */
    public C509CertificationRequestTemplate(int templateType, int[] requestTypes,
        C509AlgorithmIdentifier[] signatureAlgorithms, RDNAttributeTemplate[] subjectTemplate,
        C509AlgorithmIdentifier[] publicKeyAlgorithms, ExtensionTemplate[] extensionsTemplate)
    {
        this.templateType = templateType;
        this.requestTypes = requestTypes == null ? null : (int[])requestTypes.clone();
        this.signatureAlgorithms = signatureAlgorithms == null ? null
            : (C509AlgorithmIdentifier[])signatureAlgorithms.clone();
        this.subjectTemplate = subjectTemplate == null ? null : (RDNAttributeTemplate[])subjectTemplate.clone();
        this.publicKeyAlgorithms = publicKeyAlgorithms == null ? null
            : (C509AlgorithmIdentifier[])publicKeyAlgorithms.clone();
        this.extensionsTemplate = extensionsTemplate == null ? null
            : (ExtensionTemplate[])extensionsTemplate.clone();
    }

    /**
     * Parse a C509 certification request template from its CBOR encoding.
     */
    public static C509CertificationRequestTemplate getInstance(byte[] encoding)
        throws IOException
    {
        CBORDecoder in = new CBORDecoder(encoding);
        int count = in.readArrayHeader();
        if (count != 7)
        {
            throw new IOException("C509CertificationRequestTemplate array must have 7 elements");
        }

        int templateType = in.readInt();
        if (templateType != TYPE_SIMPLE)
        {
            throw new IOException("unsupported c509CertificationRequestTemplateType: " + templateType);
        }

        int[] requestTypes = null;
        if (!consumeUndefined(in))
        {
            int typeCount = in.readArrayHeader();
            if (typeCount == 0)
            {
                throw new IOException("c509CertificationRequestType array cannot be empty");
            }
            requestTypes = new int[typeCount];
            for (int i = 0; i != typeCount; i++)
            {
                requestTypes[i] = in.readInt();
            }
        }

        C509AlgorithmIdentifier[] signatureAlgorithms = null;
        if (!consumeUndefined(in))
        {
            signatureAlgorithms = readAlgorithms(in, true);
        }

        RDNAttributeTemplate[] subjectTemplate = null;
        if (!consumeUndefined(in))
        {
            subjectTemplate = readNameTemplate(in);
        }

        C509AlgorithmIdentifier[] publicKeyAlgorithms = null;
        if (!consumeUndefined(in))
        {
            publicKeyAlgorithms = readAlgorithms(in, false);
        }

        // subjectPublicKey always has the value undefined in the template
        in.readUndefined();

        ExtensionTemplate[] extensionsTemplate = null;
        if (!consumeUndefined(in))
        {
            extensionsTemplate = readExtensionsTemplate(in);
        }

        in.expectEnd();
        return new C509CertificationRequestTemplate(templateType, requestTypes, signatureAlgorithms,
            subjectTemplate, publicKeyAlgorithms, extensionsTemplate);
    }

    private static boolean consumeUndefined(CBORDecoder in)
        throws IOException
    {
        if (in.nextIsUndefined())
        {
            in.readUndefined();
            return true;
        }
        return false;
    }

    private static C509AlgorithmIdentifier[] readAlgorithms(CBORDecoder in, boolean signatureRegistry)
        throws IOException
    {
        int count = in.readArrayHeader();
        if (count == 0)
        {
            throw new IOException("AlgorithmIdentifier array cannot be empty");
        }
        C509AlgorithmIdentifier[] algorithms = new C509AlgorithmIdentifier[count];
        for (int i = 0; i != count; i++)
        {
            algorithms[i] = signatureRegistry
                ? C509AlgorithmIdentifier.parseSignatureAlgorithm(in)
                : C509AlgorithmIdentifier.parsePublicKeyAlgorithm(in);
        }
        return algorithms;
    }

    private static RDNAttributeTemplate[] readNameTemplate(CBORDecoder in)
        throws IOException
    {
        int count = in.readArrayHeader();
        if (count % 4 != 0)
        {
            throw new IOException("C509 NameTemplate must hold groups of 4 elements");
        }
        RDNAttributeTemplate[] attributes = new RDNAttributeTemplate[count / 4];
        for (int i = 0; i != attributes.length; i++)
        {
            Integer registryValue = null;
            ASN1ObjectIdentifier oid = null;
            if (in.peekMajorType() == CBORType.BYTE_STRING)
            {
                oid = C509Oids.fromContents(in.readByteString());
            }
            else
            {
                // negative attributeType is not allowed in a template (Section 4.4)
                long value = in.readUnsignedInteger();
                if (value > Integer.MAX_VALUE || C509AttributeType.getOID((int)value) == null)
                {
                    throw new IOException("unknown C509 RDN attribute value: " + value);
                }
                registryValue = Integers.valueOf((int)value);
            }
            long minOccurs = in.readUnsignedInteger();
            long maxOccurs = in.readUnsignedInteger();
            if (maxOccurs < minOccurs || maxOccurs < 1)
            {
                throw new IOException("C509 RDNAttributeTemplate occurrence bounds out of order");
            }
            byte[] valueEncoding = null;
            if (!consumeUndefined(in))
            {
                valueEncoding = in.readEncodedItem();
            }
            attributes[i] = new RDNAttributeTemplate(registryValue, oid, minOccurs, maxOccurs, valueEncoding);
        }
        return attributes;
    }

    private static ExtensionTemplate[] readExtensionsTemplate(CBORDecoder in)
        throws IOException
    {
        int count = in.readArrayHeader();
        if (count % 3 != 0)
        {
            throw new IOException("C509 ExtensionsTemplate must hold groups of 3 elements");
        }
        ExtensionTemplate[] extensions = new ExtensionTemplate[count / 3];
        for (int i = 0; i != extensions.length; i++)
        {
            Integer registryValue = null;
            ASN1ObjectIdentifier oid = null;
            if (in.peekMajorType() == CBORType.BYTE_STRING)
            {
                oid = C509Oids.fromContents(in.readByteString());
            }
            else
            {
                // negative extensionID is not allowed in a template (Section 4.4)
                long value = in.readUnsignedInteger();
                if (value > Integer.MAX_VALUE || C509ExtensionType.getOID((int)value) == null)
                {
                    throw new IOException("unknown C509 extension value: " + value);
                }
                registryValue = Integers.valueOf((int)value);
            }
            boolean optional = in.readBoolean();
            byte[] valueEncoding = null;
            if (!consumeUndefined(in))
            {
                valueEncoding = in.readEncodedItem();
            }
            if (registryValue != null)
            {
                extensions[i] = new ExtensionTemplate(registryValue.intValue(), optional, valueEncoding);
            }
            else
            {
                extensions[i] = new ExtensionTemplate(oid, optional, valueEncoding);
            }
        }
        return extensions;
    }

    /**
     * Return the complete CBOR encoding of this template.
     */
    public byte[] getEncoded()
        throws IOException
    {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        CBOREncoder out = new CBOREncoder(bOut);
        out.writeArrayHeader(7);
        out.writeInteger(templateType);
        if (requestTypes == null)
        {
            out.writeUndefined();
        }
        else
        {
            out.writeArrayHeader(requestTypes.length);
            for (int i = 0; i != requestTypes.length; i++)
            {
                out.writeInteger(requestTypes[i]);
            }
        }
        writeAlgorithms(out, signatureAlgorithms);
        if (subjectTemplate == null)
        {
            out.writeUndefined();
        }
        else
        {
            out.writeArrayHeader(4 * subjectTemplate.length);
            for (int i = 0; i != subjectTemplate.length; i++)
            {
                RDNAttributeTemplate attribute = subjectTemplate[i];
                if (attribute.registryValue != null)
                {
                    out.writeInteger(attribute.registryValue.intValue());
                }
                else
                {
                    out.writeByteString(C509Oids.toContents(attribute.oid));
                }
                out.writeUnsignedInteger(attribute.minOccurs);
                out.writeUnsignedInteger(attribute.maxOccurs);
                if (attribute.valueEncoding == null)
                {
                    out.writeUndefined();
                }
                else
                {
                    out.writeEncoded(attribute.valueEncoding);
                }
            }
        }
        writeAlgorithms(out, publicKeyAlgorithms);
        out.writeUndefined();
        if (extensionsTemplate == null)
        {
            out.writeUndefined();
        }
        else
        {
            out.writeArrayHeader(3 * extensionsTemplate.length);
            for (int i = 0; i != extensionsTemplate.length; i++)
            {
                ExtensionTemplate extension = extensionsTemplate[i];
                if (extension.registryValue != null)
                {
                    out.writeInteger(extension.registryValue.intValue());
                }
                else
                {
                    out.writeByteString(C509Oids.toContents(extension.oid));
                }
                out.writeBoolean(extension.optional);
                if (extension.valueEncoding == null)
                {
                    out.writeUndefined();
                }
                else
                {
                    out.writeEncoded(extension.valueEncoding);
                }
            }
        }
        return bOut.toByteArray();
    }

    private static void writeAlgorithms(CBOREncoder out, C509AlgorithmIdentifier[] algorithms)
        throws IOException
    {
        if (algorithms == null)
        {
            out.writeUndefined();
            return;
        }
        out.writeArrayHeader(algorithms.length);
        for (int i = 0; i != algorithms.length; i++)
        {
            algorithms[i].encodeTo(out);
        }
    }

    public int getTemplateType()
    {
        return templateType;
    }

    /**
     * Return the certification request types the server accepts, or null when the
     * client chooses.
     */
    public int[] getCertificationRequestTypes()
    {
        return requestTypes == null ? null : (int[])requestTypes.clone();
    }

    /**
     * Return the subject signature algorithms the server accepts, or null when the
     * client chooses.
     */
    public C509AlgorithmIdentifier[] getSubjectSignatureAlgorithms()
    {
        return signatureAlgorithms == null ? null : (C509AlgorithmIdentifier[])signatureAlgorithms.clone();
    }

    /**
     * Return the subject name template, or null when the client provides the subject.
     */
    public RDNAttributeTemplate[] getSubjectTemplate()
    {
        return subjectTemplate == null ? null : (RDNAttributeTemplate[])subjectTemplate.clone();
    }

    /**
     * Return the subject public key algorithms the server accepts, or null when the
     * client chooses.
     */
    public C509AlgorithmIdentifier[] getSubjectPublicKeyAlgorithms()
    {
        return publicKeyAlgorithms == null ? null : (C509AlgorithmIdentifier[])publicKeyAlgorithms.clone();
    }

    /**
     * Return the extensions template, or null when the client chooses the extension
     * request.
     */
    public ExtensionTemplate[] getExtensionsTemplate()
    {
        return extensionsTemplate == null ? null : (ExtensionTemplate[])extensionsTemplate.clone();
    }
}
