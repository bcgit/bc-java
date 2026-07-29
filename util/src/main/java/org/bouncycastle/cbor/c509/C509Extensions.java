package org.bouncycastle.cbor.c509;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.cbor.CBORDecoder;
import org.bouncycastle.cbor.CBOREncoder;
import org.bouncycastle.cbor.CBORType;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Integers;

/**
 * The C509 extensions field (Section 3.1.10 of draft-ietf-cose-cbor-encoded-cert-20):
 * <pre>
 * Extensions = [ * Extension ] / int
 * </pre>
 * An omitted X.509 extensions field is an empty CBOR array. When the only extension
 * present is an int-coded keyUsage, the array is elided and the field is a single
 * CBOR int whose absolute value is the keyUsage value and whose sign is the
 * criticality.
 */
public class C509Extensions
{
    private final C509Extension[] extensions;

    C509Extensions(C509Extension[] extensions)
    {
        this.extensions = extensions;
    }

    /**
     * Build the C509 form of a set of X.509 extensions. Extensions in the C509
     * Extensions Registry whose values the specific CBOR encodings of Section 3.3 can
     * faithfully represent use the int-coded form; everything else is carried in the
     * generic ~oid form. Passing null (an absent X.509 extensions field) yields an
     * empty extension list.
     */
    public static C509Extensions fromX509Extensions(Extensions x509Extensions)
    {
        if (x509Extensions == null)
        {
            return new C509Extensions(new C509Extension[0]);
        }
        ASN1ObjectIdentifier[] oids = x509Extensions.getExtensionOIDs();
        C509Extension[] result = new C509Extension[oids.length];
        for (int i = 0; i != oids.length; i++)
        {
            Extension ext = x509Extensions.getExtension(oids[i]);
            byte[] extnValue = ext.getExtnValue().getOctets();
            boolean critical = ext.isCritical();
            Integer registryValue = C509ExtensionType.getValue(oids[i]);
            byte[] cborValue = null;
            if (registryValue != null)
            {
                cborValue = C509ExtensionValueCodec.encodeValue(registryValue.intValue(), extnValue);
                if (cborValue != null && !decodesBackTo(registryValue.intValue(), cborValue, extnValue))
                {
                    // the specific encoding does not reproduce this exact DER; use the
                    // generic form so the extension still converts faithfully
                    cborValue = null;
                }
            }
            if (cborValue != null)
            {
                result[i] = new C509Extension(registryValue, oids[i], critical, cborValue, extnValue);
            }
            else
            {
                result[i] = new C509Extension(null, oids[i], critical, null, extnValue);
            }
        }
        return new C509Extensions(result);
    }

    private static boolean decodesBackTo(int registryValue, byte[] cborValue, byte[] extnValue)
    {
        try
        {
            CBORDecoder in = new CBORDecoder(cborValue);
            byte[] der = C509ExtensionValueCodec.decodeValue(registryValue, in);
            in.expectEnd();
            return Arrays.areEqual(der, extnValue);
        }
        catch (IOException e)
        {
            return false;
        }
    }

    /**
     * Parse the extensions field.
     */
    static C509Extensions parse(CBORDecoder in)
        throws IOException
    {
        int major = in.peekMajorType();
        if (major == CBORType.UNSIGNED_INTEGER || major == CBORType.NEGATIVE_INTEGER)
        {
            // single keyUsage extension compacted to one int
            long value = in.readInteger();
            boolean critical = value < 0;
            long keyUsage = critical ? -value : value;
            ByteArrayOutputStream bOut = new ByteArrayOutputStream();
            new CBOREncoder(bOut).writeUnsignedInteger(keyUsage);
            byte[] cborValue = bOut.toByteArray();
            return new C509Extensions(new C509Extension[]
                { buildRegistered(C509ExtensionType.KEY_USAGE, critical, cborValue) });
        }

        int count = in.readArrayHeader();
        if ((count & 1) != 0)
        {
            throw new IOException("C509 Extensions array must hold (extensionID, extensionValue) pairs");
        }
        C509Extension[] extensions = new C509Extension[count / 2];
        for (int i = 0; i != extensions.length; i++)
        {
            extensions[i] = parseExtension(in);
        }
        if (extensions.length == 1 && extensions[0].getRegistryValue() != null
            && extensions[0].getRegistryValue().intValue() == C509ExtensionType.KEY_USAGE)
        {
            // re-encoding applies the int compaction of Section 3.1.10, so an
            // uncompacted single keyUsage would not round-trip; the only shape the
            // compaction cannot carry is a critical keyUsage of value 0
            long keyUsage = new CBORDecoder(extensions[0].getCborValue()).readUnsignedInteger();
            if (keyUsage != 0 || !extensions[0].isCritical())
            {
                throw new IOException("single keyUsage extension must use its compacted int encoding");
            }
        }
        return new C509Extensions(extensions);
    }

    private static C509Extension parseExtension(CBORDecoder in)
        throws IOException
    {
        int major = in.peekMajorType();
        if (major == CBORType.UNSIGNED_INTEGER || major == CBORType.NEGATIVE_INTEGER)
        {
            int idValue = in.readInt();
            boolean critical = idValue < 0;
            int registryValue = critical ? -idValue : idValue;
            if (registryValue == 0)
            {
                throw new IOException("C509 extensionID cannot be 0");
            }
            byte[] cborValue = in.readEncodedItem();
            return buildRegistered(registryValue, critical, cborValue);
        }

        if (major == CBORType.BYTE_STRING)
        {
            ASN1ObjectIdentifier oid = C509Oids.fromContents(in.readByteString());
            boolean critical = false;
            byte[] extnValue;
            if (in.peekMajorType() == CBORType.ARRAY)
            {
                int count = in.readArrayHeader();
                if (count != 1)
                {
                    throw new IOException("C509 critical extension array must hold exactly one byte string");
                }
                critical = true;
                extnValue = in.readByteString();
            }
            else
            {
                extnValue = in.readByteString();
            }
            return new C509Extension(null, oid, critical, null, extnValue);
        }

        throw new IOException("C509 extensionID expected, found major type " + major);
    }

    private static C509Extension buildRegistered(int registryValue, boolean critical, byte[] cborValue)
        throws IOException
    {
        ASN1ObjectIdentifier oid = C509ExtensionType.getOID(registryValue);
        if (oid == null)
        {
            throw new IOException("unknown C509 extension value: " + registryValue);
        }
        CBORDecoder valueIn = new CBORDecoder(cborValue);
        byte[] extnValue = C509ExtensionValueCodec.decodeValue(registryValue, valueIn);
        valueIn.expectEnd();
        return new C509Extension(Integers.valueOf(registryValue), oid, critical, cborValue, extnValue);
    }

    void encodeTo(CBOREncoder out)
        throws IOException
    {
        // single int-coded keyUsage collapses to one int (unless the value is 0 and
        // the extension critical, where the sign cannot be carried)
        if (extensions.length == 1 && extensions[0].getRegistryValue() != null
            && extensions[0].getRegistryValue().intValue() == C509ExtensionType.KEY_USAGE)
        {
            long keyUsage = new CBORDecoder(extensions[0].getCborValue()).readUnsignedInteger();
            if (keyUsage != 0 || !extensions[0].isCritical())
            {
                out.writeInteger(extensions[0].isCritical() ? -keyUsage : keyUsage);
                return;
            }
        }

        out.writeArrayHeader(2 * extensions.length);
        for (int i = 0; i != extensions.length; i++)
        {
            C509Extension ext = extensions[i];
            if (ext.getRegistryValue() != null)
            {
                int id = ext.getRegistryValue().intValue();
                out.writeInteger(ext.isCritical() ? -id : id);
                out.writeEncoded(ext.getCborValue());
            }
            else
            {
                out.writeByteString(C509Oids.toContents(ext.getExtnId()));
                if (ext.isCritical())
                {
                    out.writeArrayHeader(1);
                }
                out.writeByteString(ext.getExtnValue());
            }
        }
    }

    /**
     * Return the number of extensions.
     */
    public int size()
    {
        return extensions.length;
    }

    /**
     * Return the extension at the given index, in certificate order.
     */
    public C509Extension getExtension(int index)
    {
        return extensions[index];
    }

    /**
     * Return the X.509 view of the extensions, or null when there are none (an
     * omitted X.509 extensions field).
     */
    public Extensions toX509Extensions()
    {
        if (extensions.length == 0)
        {
            return null;
        }
        Extension[] result = new Extension[extensions.length];
        for (int i = 0; i != extensions.length; i++)
        {
            result[i] = new Extension(extensions[i].getExtnId(), extensions[i].isCritical(),
                extensions[i].getExtnValue());
        }
        return new Extensions(result);
    }
}
