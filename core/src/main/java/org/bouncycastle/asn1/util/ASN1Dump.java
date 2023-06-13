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
    static void _dumpAsString(
        String      indent,
        boolean     verbose,
        ASN1Primitive obj,
        StringBuffer    buf)
    {
        String nl = Strings.lineSeparator();
        if (obj instanceof ASN1Null)
        {
            buf.append(indent);
            buf.append("NULL");
            buf.append(nl);
        }
        else if (obj instanceof ASN1Sequence)
        {
            buf.append(indent);
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
            buf.append(indent);
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
            buf.append(indent);
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
                buf.append(" IMPLICIT ");
            }

            buf.append(nl);

            String baseIndent = indent + TAB;

            _dumpAsString(baseIndent, verbose, o.getBaseObject().toASN1Primitive(), buf);
        }
        else if (obj instanceof ASN1OctetString)
        {
            ASN1OctetString oct = (ASN1OctetString)obj;

            if (obj instanceof BEROctetString)
            {
                buf.append(indent + "BER Constructed Octet String" + "[" + oct.getOctets().length + "] ");
            }
            else
            {
                buf.append(indent + "DER Octet String" + "[" + oct.getOctets().length + "] ");
            }
            if (verbose)
            {
                buf.append(dumpBinaryDataAsString(indent, oct.getOctets()));
            }
            else
            {
                buf.append(nl);
            }
        }
        else if (obj instanceof ASN1ObjectIdentifier)
        {
            buf.append(indent + "ObjectIdentifier(" + ((ASN1ObjectIdentifier)obj).getId() + ")" + nl);
        }
        else if (obj instanceof ASN1RelativeOID)
        {
            buf.append(indent + "RelativeOID(" + ((ASN1RelativeOID)obj).getId() + ")" + nl);
        }
        else if (obj instanceof ASN1Boolean)
        {
            buf.append(indent + "Boolean(" + ((ASN1Boolean)obj).isTrue() + ")" + nl);
        }
        else if (obj instanceof ASN1Integer)
        {
            buf.append(indent + "Integer(" + ((ASN1Integer)obj).getValue() + ")" + nl);
        }
        else if (obj instanceof ASN1BitString)
        {
            ASN1BitString bitString = (ASN1BitString)obj;

            byte[] bytes = bitString.getBytes();
            int padBits = bitString.getPadBits();

            if (bitString instanceof DERBitString)
            {
                buf.append(indent + "DER Bit String" + "[" + bytes.length + ", " + padBits + "] ");
            }
            else if (bitString instanceof DLBitString)
            {
                buf.append(indent + "DL Bit String" + "[" + bytes.length + ", " + padBits + "] ");
            }
            else
            {
                buf.append(indent + "BER Bit String" + "[" + bytes.length + ", " + padBits + "] ");
            }

            if (verbose)
            {
                buf.append(dumpBinaryDataAsString(indent, bytes));
            }
            else
            {
                buf.append(nl);
            }
        }
        else if (obj instanceof ASN1IA5String)
        {
            buf.append(indent + "IA5String(" + ((ASN1IA5String)obj).getString() + ") " + nl);
        }
        else if (obj instanceof ASN1UTF8String)
        {
            buf.append(indent + "UTF8String(" + ((ASN1UTF8String)obj).getString() + ") " + nl);
        }
        else if (obj instanceof ASN1NumericString)
        {
            buf.append(indent + "NumericString(" + ((ASN1NumericString)obj).getString() + ") " + nl);
        }
        else if (obj instanceof ASN1PrintableString)
        {
            buf.append(indent + "PrintableString(" + ((ASN1PrintableString)obj).getString() + ") " + nl);
        }
        else if (obj instanceof ASN1VisibleString)
        {
            buf.append(indent + "VisibleString(" + ((ASN1VisibleString)obj).getString() + ") " + nl);
        }
        else if (obj instanceof ASN1BMPString)
        {
            buf.append(indent + "BMPString(" + ((ASN1BMPString)obj).getString() + ") " + nl);
        }
        else if (obj instanceof ASN1T61String)
        {
            buf.append(indent + "T61String(" + ((ASN1T61String)obj).getString() + ") " + nl);
        }
        else if (obj instanceof ASN1GraphicString)
        {
            buf.append(indent + "GraphicString(" + ((ASN1GraphicString)obj).getString() + ") " + nl);
        }
        else if (obj instanceof ASN1VideotexString)
        {
            buf.append(indent + "VideotexString(" + ((ASN1VideotexString)obj).getString() + ") " + nl);
        }
        else if (obj instanceof ASN1UTCTime)
        {
            buf.append(indent + "UTCTime(" + ((ASN1UTCTime)obj).getTime() + ") " + nl);
        }
        else if (obj instanceof ASN1GeneralizedTime)
        {
            buf.append(indent + "GeneralizedTime(" + ((ASN1GeneralizedTime)obj).getTime() + ") " + nl);
        }
        else if (obj instanceof ASN1Enumerated)
        {
            ASN1Enumerated en = (ASN1Enumerated) obj;
            buf.append(indent + "DER Enumerated(" + en.getValue() + ")" + nl);
        }
        else if (obj instanceof ASN1ObjectDescriptor)
        {
            ASN1ObjectDescriptor od = (ASN1ObjectDescriptor)obj;
            buf.append(indent + "ObjectDescriptor(" + od.getBaseGraphicString().getString() + ") " + nl);
        }
        else if (obj instanceof ASN1External)
        {
            ASN1External ext = (ASN1External) obj;
            buf.append(indent + "External " + nl);
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
            buf.append(indent + obj.toString() + nl);
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

    private static String dumpBinaryDataAsString(String indent, byte[] bytes)
    {
        String nl = Strings.lineSeparator();
        StringBuffer buf = new StringBuffer();

        indent += TAB;
        
        buf.append(nl);
        for (int i = 0; i < bytes.length; i += SAMPLE_SIZE)
        {
            if (bytes.length - i > SAMPLE_SIZE)
            {
                buf.append(indent);
                buf.append(Strings.fromByteArray(Hex.encode(bytes, i, SAMPLE_SIZE)));
                buf.append(TAB);
                buf.append(calculateAscString(bytes, i, SAMPLE_SIZE));
                buf.append(nl);
            }
            else
            {
                buf.append(indent);
                buf.append(Strings.fromByteArray(Hex.encode(bytes, i, bytes.length - i)));
                for (int j = bytes.length - i; j != SAMPLE_SIZE; j++)
                {
                    buf.append("  ");
                }
                buf.append(TAB);
                buf.append(calculateAscString(bytes, i, bytes.length - i));
                buf.append(nl);
            }
        }
        
        return buf.toString();
    }

    private static String calculateAscString(byte[] bytes, int off, int len)
    {
        StringBuffer buf = new StringBuffer();

        for (int i = off; i != off + len; i++)
        {
            if (bytes[i] >= ' ' && bytes[i] <= '~')
            {
                buf.append((char)bytes[i]);
            }
        }

        return buf.toString();
    }
}
