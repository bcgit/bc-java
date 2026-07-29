package org.bouncycastle.cbor.c509;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1IA5String;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1PrintableString;
import org.bouncycastle.asn1.ASN1UTF8String;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cbor.CBORDecoder;
import org.bouncycastle.cbor.CBOREncoder;
import org.bouncycastle.cbor.CBORType;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Exceptions;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;

/**
 * A C509 Name (Section 3.1.4 of draft-ietf-cose-cbor-encoded-cert-20):
 * <pre>
 * Name = [ * RDNAttribute ] / SpecialText
 * RDNAttribute = ( ( attributeType: int, attributeValue: SpecialText ) //
 *                  ( attributeType: ~oid, attributeValue: bytes ) )
 * SpecialText = text / bytes / tag
 * </pre>
 * For an int-coded attribute the absolute value of the int is the C509 RDN Attributes
 * Registry value and the sign carries the DER string type (positive for utf8String,
 * negative for printableString; attributes that are always IA5String use a
 * non-negative int). Text values are compacted: a string of even length holding only
 * the symbols '0'-'9' and 'a'-'f' becomes a CBOR byte string, and an EUI-64 of the
 * form "HH-HH-HH-HH-HH-HH-HH-HH" (with "HH-HH-HH-FF-FE-HH-HH-HH" reduced to its
 * EUI-48 form) becomes a CBOR tag 48 item. A Name consisting of a single common name
 * attribute of type utf8String is encoded as just the attribute value.
 * <p>
 * Instances always hold both the CBOR encoding and the equivalent {@link X500Name},
 * so conversion failures surface at construction rather than at use. A
 * RelativeDistinguishedName with more than one AttributeTypeAndValue has no C509
 * encoding and is rejected.
 */
public class C509Name
{
    /** CBOR tag for a MAC address, RFC 9542 Section 2.4. */
    private static final long TAG_MAC_ADDRESS = 48;

    private final byte[] encoded;
    private final X500Name x500Name;

    private C509Name(byte[] encoded, X500Name x500Name)
    {
        this.encoded = encoded;
        this.x500Name = x500Name;
    }

    /**
     * Parse a C509 Name from its complete CBOR encoding.
     */
    public static C509Name getInstance(byte[] cborEncoding)
        throws IOException
    {
        CBORDecoder in = new CBORDecoder(cborEncoding);
        C509Name name = parse(in);
        in.expectEnd();
        return name;
    }

    /**
     * Parse a C509 Name from a decoder, validating it fully and materializing the
     * X.500 view.
     */
    static C509Name parse(CBORDecoder in)
        throws IOException
    {
        byte[] encoded = in.readEncodedItem();
        return new C509Name(encoded, toX500Name(encoded));
    }

    /**
     * Build the C509 form of an X.500 name.
     *
     * @throws IllegalArgumentException if the name cannot be represented in C509 -
     *         only names whose RDNs are all single-valued can be.
     */
    public static C509Name fromX500Name(X500Name name)
    {
        try
        {
            byte[] encoded = encodeX500Name(name);
            return new C509Name(encoded, name);
        }
        catch (IOException e)
        {
            throw Exceptions.illegalArgumentException("unable to encode name: " + e.getMessage(), e);
        }
    }

    /**
     * Return the X.500 view of this name.
     */
    public X500Name toX500Name()
    {
        return x500Name;
    }

    /**
     * Return the CBOR encoding of this name.
     */
    public byte[] getEncoded()
    {
        return Arrays.clone(encoded);
    }

    void encodeTo(CBOREncoder out)
        throws IOException
    {
        out.writeEncoded(encoded);
    }

    public boolean equals(Object o)
    {
        if (o == this)
        {
            return true;
        }
        if (!(o instanceof C509Name))
        {
            return false;
        }
        return Arrays.areEqual(encoded, ((C509Name)o).encoded);
    }

    public int hashCode()
    {
        return Arrays.hashCode(encoded);
    }

    /*
     * X500Name -> CBOR
     */
    private static byte[] encodeX500Name(X500Name name)
        throws IOException
    {
        RDN[] rdns = name.getRDNs();

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        CBOREncoder out = new CBOREncoder(bOut);

        // single common name attribute of type utf8String collapses to its value
        if (rdns.length == 1 && !rdns[0].isMultiValued())
        {
            AttributeTypeAndValue atv = rdns[0].getFirst();
            Integer code = C509AttributeType.getValue(atv.getType());
            if (code != null && code.intValue() == C509AttributeType.COMMON_NAME
                && atv.getValue() instanceof ASN1UTF8String)
            {
                writeSpecialText(out, ((ASN1UTF8String)atv.getValue()).getString());
                return bOut.toByteArray();
            }
        }

        int count = 0;
        for (int i = 0; i != rdns.length; i++)
        {
            if (rdns[i].isMultiValued())
            {
                throw new IOException("RelativeDistinguishedName with more than one AttributeTypeAndValue is not supported");
            }
            count += 2;
        }

        out.writeArrayHeader(count);
        for (int i = 0; i != rdns.length; i++)
        {
            AttributeTypeAndValue atv = rdns[i].getFirst();
            writeAttribute(out, atv);
        }
        return bOut.toByteArray();
    }

    private static void writeAttribute(CBOREncoder out, AttributeTypeAndValue atv)
        throws IOException
    {
        Integer code = C509AttributeType.getValue(atv.getType());
        ASN1Encodable value = atv.getValue();

        if (code != null)
        {
            int c = code.intValue();
            if (C509AttributeType.isAlwaysIA5String(c))
            {
                if (value instanceof ASN1IA5String)
                {
                    out.writeInteger(c);
                    writeSpecialText(out, ((ASN1IA5String)value).getString());
                    return;
                }
            }
            else if (value instanceof ASN1UTF8String)
            {
                out.writeInteger(c);
                writeSpecialText(out, ((ASN1UTF8String)value).getString());
                return;
            }
            else if (value instanceof ASN1PrintableString && c > 0)
            {
                out.writeInteger(-c);
                writeSpecialText(out, ((ASN1PrintableString)value).getString());
                return;
            }
        }

        // generic form: (attributeType: ~oid, attributeValue: bytes)
        out.writeByteString(C509Oids.toContents(atv.getType()));
        out.writeByteString(value.toASN1Primitive().getEncoded(ASN1Encoding.DER));
    }

    static void writeSpecialText(CBOREncoder out, String text)
        throws IOException
    {
        if (isHexString(text))
        {
            out.writeByteString(Hex.decodeStrict(text));
            return;
        }
        byte[] eui = parseEUI64(text);
        if (eui != null)
        {
            out.writeTag(TAG_MAC_ADDRESS);
            out.writeByteString(eui);
            return;
        }
        out.writeTextString(text);
    }

    private static boolean isHexString(String s)
    {
        int len = s.length();
        if (len < 2 || (len & 1) != 0)
        {
            return false;
        }
        for (int i = 0; i != len; i++)
        {
            char c = s.charAt(i);
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
            {
                return false;
            }
        }
        return true;
    }

    /**
     * Return the tag 48 content for a text string holding an EUI-64 of the form
     * "HH-HH-HH-HH-HH-HH-HH-HH" where each H is one of '0'-'9' or 'A'-'F': 6 octets
     * when the middle octets are FF-FE (an encapsulated EUI-48), 8 octets otherwise,
     * or null when the text is not of that form.
     */
    private static byte[] parseEUI64(String s)
    {
        if (s.length() != 23)
        {
            return null;
        }
        byte[] raw = new byte[8];
        for (int i = 0; i != 8; i++)
        {
            int off = i * 3;
            if (i != 7 && s.charAt(off + 2) != '-')
            {
                return null;
            }
            int hi = hexUpper(s.charAt(off));
            int lo = hexUpper(s.charAt(off + 1));
            if (hi < 0 || lo < 0)
            {
                return null;
            }
            raw[i] = (byte)((hi << 4) | lo);
        }
        if (raw[3] == (byte)0xFF && raw[4] == (byte)0xFE)
        {
            byte[] eui48 = new byte[6];
            System.arraycopy(raw, 0, eui48, 0, 3);
            System.arraycopy(raw, 5, eui48, 3, 3);
            return eui48;
        }
        return raw;
    }

    private static int hexUpper(char c)
    {
        if (c >= '0' && c <= '9')
        {
            return c - '0';
        }
        if (c >= 'A' && c <= 'F')
        {
            return c - 'A' + 10;
        }
        return -1;
    }

    /*
     * CBOR -> X500Name
     */
    private static X500Name toX500Name(byte[] encoded)
        throws IOException
    {
        CBORDecoder in = new CBORDecoder(encoded);
        int major = in.peekMajorType();

        if (major != CBORType.ARRAY)
        {
            // single common name attribute of type utf8String
            String cn = readSpecialText(in);
            in.expectEnd();
            return buildX500Name(new AttributeTypeAndValue[]
                { new AttributeTypeAndValue(C509AttributeType.getOID(C509AttributeType.COMMON_NAME), new DERUTF8String(cn)) });
        }

        int count = in.readArrayHeader();
        if ((count & 1) != 0)
        {
            throw new IOException("C509 Name array must hold (attributeType, attributeValue) pairs");
        }
        AttributeTypeAndValue[] atvs = new AttributeTypeAndValue[count / 2];
        for (int i = 0; i != atvs.length; i++)
        {
            atvs[i] = readAttribute(in);
        }
        in.expectEnd();
        return buildX500Name(atvs);
    }

    private static AttributeTypeAndValue readAttribute(CBORDecoder in)
        throws IOException
    {
        int major = in.peekMajorType();
        if (major == CBORType.UNSIGNED_INTEGER || major == CBORType.NEGATIVE_INTEGER)
        {
            int typeValue = in.readInt();
            int code = typeValue < 0 ? -typeValue : typeValue;
            ASN1ObjectIdentifier oid = C509AttributeType.getOID(code);
            if (oid == null)
            {
                throw new IOException("unknown C509 RDN attribute value: " + code);
            }
            String text = readSpecialText(in);
            ASN1Encodable value;
            if (C509AttributeType.isAlwaysIA5String(code))
            {
                if (typeValue < 0)
                {
                    throw new IOException("C509 RDN attribute " + code + " is always IA5String and must be non-negative");
                }
                value = new DERIA5String(text);
            }
            else if (typeValue < 0)
            {
                value = new DERPrintableString(text);
            }
            else
            {
                value = new DERUTF8String(text);
            }
            return new AttributeTypeAndValue(oid, value);
        }

        if (major == CBORType.BYTE_STRING)
        {
            ASN1ObjectIdentifier oid = C509Oids.fromContents(in.readByteString());
            byte[] valueEncoding = in.readByteString();
            ASN1Primitive value;
            try
            {
                value = ASN1Primitive.fromByteArray(valueEncoding);
            }
            catch (RuntimeException e)
            {
                throw Exceptions.ioException("malformed C509 RDN attribute value", e);
            }
            return new AttributeTypeAndValue(oid, value);
        }

        throw new IOException("C509 RDN attribute type expected, found major type " + major);
    }

    /**
     * Read a SpecialText item, returning the text it stands for: a byte string is
     * lowercase hex, a tag 48 MAC address is its EUI-64 text form, and a text string
     * is itself.
     */
    static String readSpecialText(CBORDecoder in)
        throws IOException
    {
        int major = in.peekMajorType();
        if (major == CBORType.TEXT_STRING)
        {
            return in.readTextString();
        }
        if (major == CBORType.BYTE_STRING)
        {
            byte[] contents = in.readByteString();
            if (contents.length == 0)
            {
                throw new IOException("C509 SpecialText byte string cannot be empty");
            }
            // -DM Hex.toHexString
            return Hex.toHexString(contents);
        }
        if (major == CBORType.TAG)
        {
            long tag = in.readTag();
            if (tag != TAG_MAC_ADDRESS)
            {
                throw new IOException("C509 SpecialText with unsupported tag " + tag);
            }
            byte[] mac = in.readByteString();
            if (mac.length == 6)
            {
                return formatEUI(new byte[]
                    { mac[0], mac[1], mac[2], (byte)0xFF, (byte)0xFE, mac[3], mac[4], mac[5] });
            }
            if (mac.length == 8)
            {
                return formatEUI(mac);
            }
            throw new IOException("C509 tagged MAC address must hold 6 or 8 octets");
        }
        throw new IOException("C509 SpecialText expected, found major type " + major);
    }

    private static String formatEUI(byte[] raw)
    {
        StringBuffer sb = new StringBuffer(23);
        for (int i = 0; i != raw.length; i++)
        {
            if (i != 0)
            {
                sb.append('-');
            }
            // -DM Hex.toHexString
            sb.append(Strings.toUpperCase(Hex.toHexString(raw, i, 1)));
        }
        return sb.toString();
    }

    private static X500Name buildX500Name(AttributeTypeAndValue[] atvs)
    {
        RDN[] rdns = new RDN[atvs.length];
        for (int i = 0; i != atvs.length; i++)
        {
            rdns[i] = new RDN(atvs[i]);
        }
        return new X500Name(rdns);
    }
}
