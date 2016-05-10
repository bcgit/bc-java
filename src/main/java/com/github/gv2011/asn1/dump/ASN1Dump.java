package com.github.gv2011.asn1.dump;

import java.io.IOException;
import java.util.Enumeration;

import com.github.gv2011.asn1.ASN1ApplicationSpecific;
import com.github.gv2011.asn1.ASN1Boolean;
import com.github.gv2011.asn1.ASN1Encodable;
import com.github.gv2011.asn1.ASN1Enumerated;
import com.github.gv2011.asn1.ASN1GeneralizedTime;
import com.github.gv2011.asn1.ASN1Integer;
import com.github.gv2011.asn1.ASN1ObjectIdentifier;
import com.github.gv2011.asn1.ASN1OctetString;
import com.github.gv2011.asn1.ASN1Primitive;
import com.github.gv2011.asn1.ASN1Sequence;
import com.github.gv2011.asn1.ASN1Set;
import com.github.gv2011.asn1.ASN1TaggedObject;
import com.github.gv2011.asn1.ASN1UTCTime;
import com.github.gv2011.asn1.BERApplicationSpecific;
import com.github.gv2011.asn1.BEROctetString;
import com.github.gv2011.asn1.BERSequence;
import com.github.gv2011.asn1.BERSet;
import com.github.gv2011.asn1.BERTaggedObject;
import com.github.gv2011.asn1.BERTags;
import com.github.gv2011.asn1.DERApplicationSpecific;
import com.github.gv2011.asn1.DERBMPString;
import com.github.gv2011.asn1.DERBitString;
import com.github.gv2011.asn1.DERExternal;
import com.github.gv2011.asn1.DERGraphicString;
import com.github.gv2011.asn1.DERIA5String;
import com.github.gv2011.asn1.DERNull;
import com.github.gv2011.asn1.DERPrintableString;
import com.github.gv2011.asn1.DERSequence;
import com.github.gv2011.asn1.DERT61String;
import com.github.gv2011.asn1.DERUTF8String;
import com.github.gv2011.asn1.DERVideotexString;
import com.github.gv2011.asn1.DERVisibleString;
import com.github.gv2011.asn1.util.Strings;
import com.github.gv2011.asn1.util.encoders.Hex;

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
        if (obj instanceof ASN1Sequence)
        {
            Enumeration     e = ((ASN1Sequence)obj).getObjects();
            String          tab = indent + TAB;

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

            while (e.hasMoreElements())
            {
                Object  o = e.nextElement();

                if (o == null || o.equals(DERNull.INSTANCE))
                {
                    buf.append(tab);
                    buf.append("NULL");
                    buf.append(nl);
                }
                else if (o instanceof ASN1Primitive)
                {
                    _dumpAsString(tab, verbose, (ASN1Primitive)o, buf);
                }
                else
                {
                    _dumpAsString(tab, verbose, ((ASN1Encodable)o).toASN1Primitive(), buf);
                }
            }
        }
        else if (obj instanceof ASN1TaggedObject)
        {
            String          tab = indent + TAB;

            buf.append(indent);
            if (obj instanceof BERTaggedObject)
            {
                buf.append("BER Tagged [");
            }
            else
            {
                buf.append("Tagged [");
            }

            ASN1TaggedObject o = (ASN1TaggedObject)obj;

            buf.append(Integer.toString(o.getTagNo()));
            buf.append(']');

            if (!o.isExplicit())
            {
                buf.append(" IMPLICIT ");
            }

            buf.append(nl);

            if (o.isEmpty())
            {
                buf.append(tab);
                buf.append("EMPTY");
                buf.append(nl);
            }
            else
            {
                _dumpAsString(tab, verbose, o.getObject(), buf);
            }
        }
        else if (obj instanceof ASN1Set)
        {
            Enumeration     e = ((ASN1Set)obj).getObjects();
            String          tab = indent + TAB;

            buf.append(indent);

            if (obj instanceof BERSet)
            {
                buf.append("BER Set");
            }
            else
            {
                buf.append("DER Set");
            }

            buf.append(nl);

            while (e.hasMoreElements())
            {
                Object  o = e.nextElement();

                if (o == null)
                {
                    buf.append(tab);
                    buf.append("NULL");
                    buf.append(nl);
                }
                else if (o instanceof ASN1Primitive)
                {
                    _dumpAsString(tab, verbose, (ASN1Primitive)o, buf);
                }
                else
                {
                    _dumpAsString(tab, verbose, ((ASN1Encodable)o).toASN1Primitive(), buf);
                }
            }
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
        else if (obj instanceof ASN1Boolean)
        {
            buf.append(indent + "Boolean(" + ((ASN1Boolean)obj).isTrue() + ")" + nl);
        }
        else if (obj instanceof ASN1Integer)
        {
            buf.append(indent + "Integer(" + ((ASN1Integer)obj).getValue() + ")" + nl);
        }
        else if (obj instanceof DERBitString)
        {
            DERBitString bt = (DERBitString)obj;
            buf.append(indent + "DER Bit String" + "[" + bt.getBytes().length + ", " + bt.getPadBits() + "] ");
            if (verbose)
            {
                buf.append(dumpBinaryDataAsString(indent, bt.getBytes()));
            }
            else
            {
                buf.append(nl);
            }
        }
        else if (obj instanceof DERIA5String)
        {
            buf.append(indent + "IA5String(" + ((DERIA5String)obj).getString() + ") " + nl);
        }
        else if (obj instanceof DERUTF8String)
        {
            buf.append(indent + "UTF8String(" + ((DERUTF8String)obj).getString() + ") " + nl);
        }
        else if (obj instanceof DERPrintableString)
        {
            buf.append(indent + "PrintableString(" + ((DERPrintableString)obj).getString() + ") " + nl);
        }
        else if (obj instanceof DERVisibleString)
        {
            buf.append(indent + "VisibleString(" + ((DERVisibleString)obj).getString() + ") " + nl);
        }
        else if (obj instanceof DERBMPString)
        {
            buf.append(indent + "BMPString(" + ((DERBMPString)obj).getString() + ") " + nl);
        }
        else if (obj instanceof DERT61String)
        {
            buf.append(indent + "T61String(" + ((DERT61String)obj).getString() + ") " + nl);
        }
        else if (obj instanceof DERGraphicString)
        {
            buf.append(indent + "GraphicString(" + ((DERGraphicString)obj).getString() + ") " + nl);
        }
        else if (obj instanceof DERVideotexString)
        {
            buf.append(indent + "VideotexString(" + ((DERVideotexString)obj).getString() + ") " + nl);
        }
        else if (obj instanceof ASN1UTCTime)
        {
            buf.append(indent + "UTCTime(" + ((ASN1UTCTime)obj).getTime() + ") " + nl);
        }
        else if (obj instanceof ASN1GeneralizedTime)
        {
            buf.append(indent + "GeneralizedTime(" + ((ASN1GeneralizedTime)obj).getTime() + ") " + nl);
        }
        else if (obj instanceof BERApplicationSpecific)
        {
            buf.append(outputApplicationSpecific("BER", indent, verbose, obj, nl));
        }
        else if (obj instanceof DERApplicationSpecific)
        {
            buf.append(outputApplicationSpecific("DER", indent, verbose, obj, nl));
        }
        else if (obj instanceof ASN1Enumerated)
        {
            ASN1Enumerated en = (ASN1Enumerated) obj;
            buf.append(indent + "DER Enumerated(" + en.getValue() + ")" + nl);
        }
        else if (obj instanceof DERExternal)
        {
            DERExternal ext = (DERExternal) obj;
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
    
    private static String outputApplicationSpecific(String type, String indent, boolean verbose, ASN1Primitive obj, String nl)
    {
        ASN1ApplicationSpecific app = ASN1ApplicationSpecific.getInstance(obj);
        StringBuffer buf = new StringBuffer();

        if (app.isConstructed())
        {
            try
            {
                ASN1Sequence s = ASN1Sequence.getInstance(app.getObject(BERTags.SEQUENCE));
                buf.append(indent + type + " ApplicationSpecific[" + app.getApplicationTag() + "]" + nl);
                for (Enumeration e = s.getObjects(); e.hasMoreElements();)
                {
                    _dumpAsString(indent + TAB, verbose, (ASN1Primitive)e.nextElement(), buf);
                }
            }
            catch (IOException e)
            {
                buf.append(e);
            }
            return buf.toString();
        }

        return indent + type + " ApplicationSpecific[" + app.getApplicationTag() + "] (" + new String(Hex.encode(app.getContents())) + ")" + nl;
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
        StringBuffer buf = new StringBuffer();

        if (obj instanceof ASN1Primitive)
        {
            _dumpAsString("", verbose, (ASN1Primitive)obj, buf);
        }
        else if (obj instanceof ASN1Encodable)
        {
            _dumpAsString("", verbose, ((ASN1Encodable)obj).toASN1Primitive(), buf);
        }
        else
        {
            return "unknown object type " + obj.toString();
        }

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
                buf.append(new String(Hex.encode(bytes, i, SAMPLE_SIZE)));
                buf.append(TAB);
                buf.append(calculateAscString(bytes, i, SAMPLE_SIZE));
                buf.append(nl);
            }
            else
            {
                buf.append(indent);
                buf.append(new String(Hex.encode(bytes, i, bytes.length - i)));
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
