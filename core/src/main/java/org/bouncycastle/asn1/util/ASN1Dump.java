package org.bouncycastle.asn1.util;

import org.bouncycastle.asn1.ASN1BMPString;
import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.ASN1External;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1GraphicString;
import org.bouncycastle.asn1.ASN1IA5String;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Null;
import org.bouncycastle.asn1.ASN1NumericString;
import org.bouncycastle.asn1.ASN1ObjectDescriptor;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1PrintableString;
import org.bouncycastle.asn1.ASN1RelativeOID;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1T61String;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.ASN1UTCTime;
import org.bouncycastle.asn1.ASN1UTF8String;
import org.bouncycastle.asn1.ASN1Util;
import org.bouncycastle.asn1.ASN1VideotexString;
import org.bouncycastle.asn1.ASN1VisibleString;
import org.bouncycastle.asn1.BEROctetString;
import org.bouncycastle.asn1.BERSequence;
import org.bouncycastle.asn1.BERSet;
import org.bouncycastle.asn1.BERTaggedObject;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DLBitString;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;

/**
 * Utility class for dumping ASN.1 objects as (hopefully) human friendly strings.
 */
public class ASN1Dump
{
    private static final String  TAB = "    ";
    private static final int SAMPLE_SIZE = 32;

    /**
     * dump a DER object as a formatted string with indentation
     *
     * @param obj the ASN1Primitive to be dumped out.
     */
    static void _dumpAsString(String indent, boolean verbose, ASN1Primitive obj, StringBuffer buf)
    {
        String nl = Strings.lineSeparator();
        buf.append(indent);

        if (obj instanceof ASN1Null)
        {
            buf.append("NULL");
            buf.append(nl);
        }
        else if (obj instanceof ASN1Sequence)
        {
            if (obj instanceof BERSequence)
            {
                buf.append("BER Sequence");
            }
            else if (obj instanceof DERSequence)
            {
                buf.append("DER Sequence");
            }
            else
            {
                buf.append("Sequence");
            }
            buf.append(nl);

            ASN1Sequence sequence = (ASN1Sequence)obj;
            String elementsIndent = indent + TAB;

            for (int i = 0, count = sequence.size(); i < count; ++i)
            {
                _dumpAsString(elementsIndent, verbose, sequence.getObjectAt(i).toASN1Primitive(), buf);
            }
        }
        else if (obj instanceof ASN1Set)
        {
            if (obj instanceof BERSet)
            {
                buf.append("BER Set");
            }
            else if (obj instanceof DERSet)
            {
                buf.append("DER Set");
            }
            else
            {
                buf.append("Set");
            }
            buf.append(nl);

            ASN1Set set = (ASN1Set)obj;
            String elementsIndent = indent + TAB;

            for (int i = 0, count = set.size(); i < count; ++i)
            {
                _dumpAsString(elementsIndent, verbose, set.getObjectAt(i).toASN1Primitive(), buf);
            }
        }
        else if (obj instanceof ASN1TaggedObject)
        {
            if (obj instanceof BERTaggedObject)
            {
                buf.append("BER Tagged ");
            }
            else if (obj instanceof DERTaggedObject)
            {
                buf.append("DER Tagged ");
            }
            else
            {
                buf.append("Tagged ");
            }

            ASN1TaggedObject o = (ASN1TaggedObject)obj;

            buf.append(ASN1Util.getTagText(o));

            if (!o.isExplicit())
            {
                buf.append(" IMPLICIT");
            }

            buf.append(nl);

            String baseIndent = indent + TAB;

            _dumpAsString(baseIndent, verbose, o.getBaseObject().toASN1Primitive(), buf);
        }
        else if (obj instanceof ASN1ObjectIdentifier)
        {
            buf.append("ObjectIdentifier(" + ((ASN1ObjectIdentifier)obj).getId() + ")" + nl);
        }
        else if (obj instanceof ASN1RelativeOID)
        {
            buf.append("RelativeOID(" + ((ASN1RelativeOID)obj).getId() + ")" + nl);
        }
        else if (obj instanceof ASN1Boolean)
        {
            buf.append("Boolean(" + ((ASN1Boolean)obj).isTrue() + ")" + nl);
        }
        else if (obj instanceof ASN1Integer)
        {
            buf.append("Integer(" + ((ASN1Integer)obj).getValue() + ")" + nl);
        }
        else if (obj instanceof ASN1OctetString)
        {
            ASN1OctetString oct = (ASN1OctetString)obj;

            if (obj instanceof BEROctetString)
            {
                buf.append("BER Constructed Octet String[");
            }
            else
            {
                buf.append("DER Octet String[");
            }

            buf.append(oct.getOctetsLength() + "]" + nl);

            if (verbose)
            {
                dumpBinaryDataAsString(buf, indent, oct.getOctets());
            }
        }
        else if (obj instanceof ASN1BitString)
        {
            ASN1BitString bitString = (ASN1BitString)obj;

            if (bitString instanceof DERBitString)
            {
                buf.append("DER Bit String[");
            }
            else if (bitString instanceof DLBitString)
            {
                buf.append("DL Bit String[");
            }
            else
            {
                buf.append("BER Bit String[");
            }

            buf.append(bitString.getBytesLength() + ", " + bitString.getPadBits() + "]" + nl);

            if (verbose)
            {
                dumpBinaryDataAsString(buf, indent, bitString.getBytes());
            }
        }
        else if (obj instanceof ASN1IA5String)
        {
            buf.append("IA5String(" + ((ASN1IA5String)obj).getString() + ") " + nl);
        }
        else if (obj instanceof ASN1UTF8String)
        {
            buf.append("UTF8String(" + ((ASN1UTF8String)obj).getString() + ") " + nl);
        }
        else if (obj instanceof ASN1NumericString)
        {
            buf.append("NumericString(" + ((ASN1NumericString)obj).getString() + ") " + nl);
        }
        else if (obj instanceof ASN1PrintableString)
        {
            buf.append("PrintableString(" + ((ASN1PrintableString)obj).getString() + ") " + nl);
        }
        else if (obj instanceof ASN1VisibleString)
        {
            buf.append("VisibleString(" + ((ASN1VisibleString)obj).getString() + ") " + nl);
        }
        else if (obj instanceof ASN1BMPString)
        {
            buf.append("BMPString(" + ((ASN1BMPString)obj).getString() + ") " + nl);
        }
        else if (obj instanceof ASN1T61String)
        {
            buf.append("T61String(" + ((ASN1T61String)obj).getString() + ") " + nl);
        }
        else if (obj instanceof ASN1GraphicString)
        {
            buf.append("GraphicString(" + ((ASN1GraphicString)obj).getString() + ") " + nl);
        }
        else if (obj instanceof ASN1VideotexString)
        {
            buf.append("VideotexString(" + ((ASN1VideotexString)obj).getString() + ") " + nl);
        }
        else if (obj instanceof ASN1UTCTime)
        {
            buf.append("UTCTime(" + ((ASN1UTCTime)obj).getTime() + ") " + nl);
        }
        else if (obj instanceof ASN1GeneralizedTime)
        {
            buf.append("GeneralizedTime(" + ((ASN1GeneralizedTime)obj).getTime() + ") " + nl);
        }
        else if (obj instanceof ASN1Enumerated)
        {
            ASN1Enumerated en = (ASN1Enumerated) obj;
            buf.append("DER Enumerated(" + en.getValue() + ")" + nl);
        }
        else if (obj instanceof ASN1ObjectDescriptor)
        {
            ASN1ObjectDescriptor od = (ASN1ObjectDescriptor)obj;
            buf.append("ObjectDescriptor(" + od.getBaseGraphicString().getString() + ") " + nl);
        }
        else if (obj instanceof ASN1External)
        {
            ASN1External ext = (ASN1External) obj;
            buf.append("External " + nl);
            String          tab = indent + TAB;
            if (ext.getDirectReference() != null)
            {
                buf.append(tab + "Direct Reference: " + ext.getDirectReference().getId() + nl);
            }
            if (ext.getIndirectReference() != null)
            {
                buf.append(tab + "Indirect Reference: " + ext.getIndirectReference().toString() + nl);
            }
            if (ext.getDataValueDescriptor() != null)
            {
                _dumpAsString(tab, verbose, ext.getDataValueDescriptor(), buf);
            }
            buf.append(tab + "Encoding: " + ext.getEncoding() + nl);
            _dumpAsString(tab, verbose, ext.getExternalContent(), buf);
        }
        else
        {
            buf.append(obj.toString() + nl);
        }
    }

    /**
     * dump out a DER object as a formatted string, in non-verbose mode.
     *
     * @param obj the ASN1Primitive to be dumped out.
     * @return  the resulting string.
     */
    public static String dumpAsString(
        Object   obj)
    {
        return dumpAsString(obj, false);
    }

    /**
     * Dump out the object as a string.
     *
     * @param obj  the object to be dumped
     * @param verbose  if true, dump out the contents of octet and bit strings.
     * @return  the resulting string.
     */
    public static String dumpAsString(
        Object   obj,
        boolean  verbose)
    {
        ASN1Primitive primitive;
        if (obj instanceof ASN1Primitive)
        {
            primitive = (ASN1Primitive)obj;
        }
        else if (obj instanceof ASN1Encodable)
        {
            primitive = ((ASN1Encodable)obj).toASN1Primitive();
        }
        else
        {
            return "unknown object type " + obj.toString();
        }

        StringBuffer buf = new StringBuffer();
        _dumpAsString("", verbose, primitive, buf);
        return buf.toString();
    }

    private static void dumpBinaryDataAsString(StringBuffer buf, String indent, byte[] bytes)
    {
        if (bytes.length < 1)
        {
            return;
        }

        String nl = Strings.lineSeparator();

        indent += TAB;

        for (int i = 0; i < bytes.length; i += SAMPLE_SIZE)
        {
            int remaining = bytes.length - i;
            int chunk = Math.min(remaining, SAMPLE_SIZE);

            buf.append(indent);
            // -DM Hex.toHexString
            buf.append(Hex.toHexString(bytes, i, chunk));
            for (int j = chunk; j < SAMPLE_SIZE; ++j)
            {
                buf.append("  ");
            }
            buf.append(TAB);
            appendAscString(buf, bytes, i, chunk);
            buf.append(nl);
        }
    }

    private static void appendAscString(StringBuffer buf, byte[] bytes, int off, int len)
    {
        for (int i = off; i != off + len; i++)
        {
            if (bytes[i] >= ' ' && bytes[i] <= '~')
            {
                buf.append((char)bytes[i]);
            }
        }
    }
}
