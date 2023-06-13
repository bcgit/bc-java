package org.bouncycastle.oer;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.List;

import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.ASN1IA5String;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.ASN1UTF8String;
import org.bouncycastle.asn1.BERTags;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.Pack;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;

public class OEROutputStream
    extends OutputStream
{
    private static final int[] bits = new int[]{1, 2, 4, 8, 16, 32, 64, 128};
    private final OutputStream out;
    protected PrintWriter debugOutput = null;

    public OEROutputStream(OutputStream out)
    {
        this.out = out;
    }

    public static int byteLength(long value)
    {
        long m = 0xFF00000000000000L;
        int j = 8;
        for (; j > 0 && (value & m) == 0; j--)
        {
            value <<= 8;
        }
        return j;
    }

    public void write(ASN1Encodable encodable, Element oerElement)
        throws IOException
    {

        if (encodable == OEROptional.ABSENT)
        {
            return;
        }
        else if (encodable instanceof OEROptional)
        {
            write(((OEROptional)encodable).get(), oerElement);
            return;
        }

        //oerElement = Element.expandDeferredDefinition(oerElement, );

        encodable = encodable.toASN1Primitive();

        switch (oerElement.getBaseType())
        {

        case Supplier:
            write(encodable, oerElement.getElementSupplier().build());
            break;
        case SEQ:
        {
            ASN1Sequence seq = ASN1Sequence.getInstance(encodable);

            // build mask.
            int j = 7;
            int mask = 0;

            //
            // Does the extension bit in the preamble need to exist and does it need to be set?
            //
            boolean extensionDefined = false;
            if (oerElement.isExtensionsInDefinition())
            {
                for (int t = 0; t < oerElement.getChildren().size(); t++)
                {
                    Element e = oerElement.getChildren().get(t);
                    if (e.getBaseType() == OERDefinition.BaseType.EXTENSION)
                    {
                        break; // Can support extensions but doesn't have any defined.
                    }

                    if ((e.getBlock() > 0 && t < seq.size()))
                    {
                        if (!OEROptional.ABSENT.equals(seq.getObjectAt(t)))
                        {
                            // Can support extensions and one or more have been defined.
                            extensionDefined = true;
                            break;
                        }
                    }
                }

                if (extensionDefined)
                {
                    mask |= bits[j];
                }
                j--;
            }

            //
            // Write optional bit mask for block 0.
            //
            for (int t = 0; t < oerElement.getChildren().size(); t++)
            {
                Element childOERDescription = oerElement.getChildren().get(t);
                if (childOERDescription.getBaseType() == OERDefinition.BaseType.EXTENSION)
                {
                    // We don't encode these, they are marker when the possibility of an extension is indicated but no actual extensions
                    // are defined as yet.
                    continue;
                }

                if (childOERDescription.getBlock() > 0)
                {
                    // We are heading into extensions now so stop here and write out the values
                    // for block 0.
                    break;
                }

                childOERDescription = Element.expandDeferredDefinition(childOERDescription, oerElement);
                if (oerElement.getaSwitch() != null)
                {
                    childOERDescription = oerElement.getaSwitch().result(new SwitchIndexer.Asn1SequenceIndexer(seq));
                    childOERDescription = Element.expandDeferredDefinition(childOERDescription, oerElement);
                }


                if (j < 0)
                {
                    out.write(mask);
                    j = 7;
                    mask = 0;
                }

                ASN1Encodable asn1EncodableChild = seq.getObjectAt(t);

                if (childOERDescription.isExplicit() && asn1EncodableChild instanceof OEROptional)
                {
                    // TODO call stack like definition error.
                    throw new IllegalStateException("absent sequence element that is required by oer definition");
                }

                if (!childOERDescription.isExplicit())
                {
                    ASN1Encodable obj = seq.getObjectAt(t);
                    if (childOERDescription.getDefaultValue() != null)
                    {

                        if (obj instanceof OEROptional)
                        {
                            if (((OEROptional)obj).isDefined())
                            {
                                if (!((OEROptional)obj).get().equals(childOERDescription.getDefaultValue()))
                                {
                                    mask |= bits[j];
                                }
                            }
                        }
                        else
                        {
                            if (!childOERDescription.getDefaultValue().equals(obj))
                            {
                                mask |= bits[j];
                            }
                        }
                    }
                    else
                    {
                        if (asn1EncodableChild != OEROptional.ABSENT)
                        {
                            mask |= bits[j];
                        }
                    }
                    j--;
                }
            }

            if (j != 7)
            {
                out.write(mask);
            }


            List<Element> childElements = oerElement.getChildren();
            //
            // Write the values for block 0.
            //
            int t;
            for (t = 0; t < childElements.size(); t++)
            {
                Element childOERElement = oerElement.getChildren().get(t);

                if (childOERElement.getBaseType() == OERDefinition.BaseType.EXTENSION)
                {
                    continue;
                }

                if (childOERElement.getBlock() > 0)
                {
                    break;
                }

                ASN1Encodable child = seq.getObjectAt(t);

                if (childOERElement.getaSwitch() != null)
                {
                    childOERElement = childOERElement.getaSwitch().result(new SwitchIndexer.Asn1SequenceIndexer(seq));
                }

                if (childOERElement.getDefaultValue() != null)
                {
                    if (childOERElement.getDefaultValue().equals(child))
                    {
                        continue;
                    }
                }
                write(child, childOERElement);
            }

            //
            // Extensions.
            //

            if (extensionDefined)
            {

                // Form presence bitmap 16.4.3
                int start = t;
                ByteArrayOutputStream presensceList = new ByteArrayOutputStream();
                j = 7;
                mask = 0;
                for (int i = start; i < childElements.size(); i++)
                {
                    if (j < 0)
                    {
                        presensceList.write(mask);
                        j = 7;
                        mask = 0;
                    }

                    if (i < seq.size() && !OEROptional.ABSENT.equals(seq.getObjectAt(i)))
                    {
                        mask |= bits[j];
                    }
                    j--;
                }

                if (j != 7)
                {
                    // Write the final set of bits.
                    presensceList.write(mask);
                }

                encodeLength(presensceList.size() + 1); // +1 = initial octet
                if (j == 7)
                {
                    write(0);
                }
                else
                {
                    write(j + 1);
                }// Initial octet 16.4.2
                write(presensceList.toByteArray());

                // Open encode the actual values.
                for (; t < childElements.size(); t++)
                {
                    // 16.5.2 Extension Addition Groups are not supported.
                    if (t < seq.size() && !OEROptional.ABSENT.equals(seq.getObjectAt(t)))
                    {
                        writePlainType(seq.getObjectAt(t), childElements.get(t));
                    }
                }
            }
            out.flush();
            debugPrint(oerElement.appendLabel(""));
        }
        break;
        case SEQ_OF:
            //
            // Assume this comes in as a sequence.
            //
            Enumeration e;
            if (encodable instanceof ASN1Set)
            {
                e = ((ASN1Set)encodable).getObjects();
                encodeQuantity(((ASN1Set)encodable).size());
            }
            else if (encodable instanceof ASN1Sequence)
            {
                e = ((ASN1Sequence)encodable).getObjects();
                encodeQuantity(((ASN1Sequence)encodable).size());
            }
            else
            {
                throw new IllegalStateException("encodable at for SEQ_OF is not a container");
            }


            Element encodingElement = Element.expandDeferredDefinition(oerElement.getFirstChid(), oerElement);

            while (e.hasMoreElements())
            {
                Object o = e.nextElement();
                write((ASN1Encodable)o, encodingElement);
            }
            out.flush();
            debugPrint(oerElement.appendLabel(""));
            break;
        case CHOICE:
        {
            ASN1Primitive item = encodable.toASN1Primitive();
            BitBuilder bb = new BitBuilder();
            int tag;

            ASN1Primitive valueToWrite = null;
            if (item instanceof ASN1TaggedObject)
            {
                ASN1TaggedObject taggedObject = (ASN1TaggedObject)item;

                //
                // Tag prefix.
                //
                int tagClass = taggedObject.getTagClass();
                bb.writeBit(tagClass & BERTags.CONTEXT_SPECIFIC)
                    .writeBit(tagClass & BERTags.APPLICATION);

                tag = taggedObject.getTagNo();
                valueToWrite = taggedObject.getBaseObject().toASN1Primitive();
            }
            else
            {
                throw new IllegalStateException("only support tagged objects");
            }

            //
            // Encode tag value.
            //

            // Small tag value encode in remaining bits
            if (tag <= 63)
            {
                bb.writeBits(tag, 6);
            }
            else
            {
                // Large tag value variant.
                bb.writeBits(0xFF, 6);
                // Encode as 7bit bytes where MSB indicated continuing byte.
                bb.write7BitBytes(tag);
            }


            if (debugOutput != null)
            {
                if (item instanceof ASN1TaggedObject)
                {
                    ASN1TaggedObject taggedObject = (ASN1TaggedObject)item;
                    if (BERTags.APPLICATION == taggedObject.getTagClass())
                    {
                        debugPrint(oerElement.appendLabel("AS"));
                    }
                    else
                    {
                        debugPrint(oerElement.appendLabel("CS"));
                    }
                }
            }


            // Save the header.
            bb.writeAndClear(out);

            Element val = oerElement.getChildren().get(tag);
            val = Element.expandDeferredDefinition(val, oerElement);

            if (val.getBlock() > 0)
            {
                writePlainType(valueToWrite, val);
            }
            else
            {
                write(valueToWrite, val);
            }
            out.flush();
            break;
        }
        case ENUM:
        {
            BigInteger ordinal;
            if (encodable instanceof ASN1Integer)
            {
                ordinal = ASN1Integer.getInstance(encodable).getValue();
            }
            else
            {
                ordinal = ASN1Enumerated.getInstance(encodable).getValue();
            }

            for (Iterator it = oerElement.getChildren().iterator(); it.hasNext(); )
            {
                Element child = (Element)it.next();
                child = Element.expandDeferredDefinition(child, oerElement);

                //
                // This by default is canonical OER, see NOTE 1 and NOTE 2, 11.14
                // Section 11.4 of T-REC-X.696-201508-I!!PDF-E.pdf
                //
                if (child.getEnumValue().equals(ordinal))
                {
                    if (ordinal.compareTo(BigInteger.valueOf(127)) > 0)
                    {
                        // Note 2 Section 11.4 of T-REC-X.696-201508-I!!PDF-E.pdf
                        byte[] val = ordinal.toByteArray();
                        int l = 0x80 | (val.length & 0xFF);
                        out.write(l);
                        out.write(val);
                    }
                    else
                    {
                        out.write(ordinal.intValue() & 0x7F);
                    }
                    out.flush();
                    debugPrint(oerElement.appendLabel(oerElement.rangeExpression()));
                    return;
                }
            }

            // -DM Hex.toHexString
            throw new IllegalArgumentException("enum value " + ordinal + " " + Hex.toHexString(ordinal.toByteArray()) + " no in defined child list");
        }
        case INT:
        {
            ASN1Integer integer = ASN1Integer.getInstance(encodable);


            // >0 = positive and <0 = negative
            int intBytesForRange = oerElement.intBytesForRange();
            if (intBytesForRange > 0)
            {
                //
                // For unsigned fixed length 1,2,4,8 byte integers.
                //
                byte[] encoded = BigIntegers.asUnsignedByteArray(intBytesForRange, integer.getValue());
                switch (intBytesForRange)
                {
                case 1:
                case 2:
                case 4:
                case 8:
                    out.write(encoded);
                    break;
                default:
                    throw new IllegalStateException("unknown uint length " + intBytesForRange);
                }
            }
            else if (intBytesForRange < 0)
            {

                //
                // For twos compliment numbers of 1,2,4,8 bytes in encoded length.
                //

                byte[] encoded;
                BigInteger number = integer.getValue();
                switch (intBytesForRange)
                {
                case -1:
                    encoded = new byte[]{BigIntegers.byteValueExact(number)};
                    break;
                case -2:
                    encoded = Pack.shortToBigEndian(BigIntegers.shortValueExact(number));
                    break;
                case -4:
                    encoded = Pack.intToBigEndian(BigIntegers.intValueExact(number));
                    break;
                case -8:
                    encoded = Pack.longToBigEndian(BigIntegers.longValueExact(number));
                    break;
                default:
                    throw new IllegalStateException("unknown twos compliment length");
                }

                out.write(encoded);
            }
            else
            {
                // Unbounded at one or both ends and needs length encoding.
                byte[] encoded;
                if (oerElement.isLowerRangeZero())
                {
                    // Since we have already captured the fixed with unsigned ints.
                    // Everything is assumed unbounded we need to encode a length and write the value.
                    encoded = BigIntegers.asUnsignedByteArray(integer.getValue());
                }
                else
                {
                    // Twos complement
                    encoded = integer.getValue().toByteArray();
                }

                encodeLength(encoded.length); // Deals with long and short forms.
                out.write(encoded);
            }
            debugPrint(oerElement.appendLabel(oerElement.rangeExpression()));
            out.flush();
        }

        break;
        case OCTET_STRING:
        {
            ASN1OctetString octets = ASN1OctetString.getInstance(encodable);
            byte[] bytes = octets.getOctets();
            if (oerElement.isFixedLength())
            {
                out.write(bytes);
            }
            else
            {
                encodeLength(bytes.length);
                out.write(bytes);
            }
            debugPrint(oerElement.appendLabel(oerElement.rangeExpression()));
            out.flush();
            break;
        }
        case IA5String:
        {
            ASN1IA5String iaf = ASN1IA5String.getInstance(encodable);
            byte[] encoded = iaf.getOctets();

            //
            // IA5Strings can be fixed length because they have a fixed multiplier.
            //
            if (oerElement.isFixedLength() && oerElement.getUpperBound().intValue() != encoded.length)
            {
                throw new IOException("IA5String string length does not equal declared fixed length "
                    + encoded.length + " " + oerElement.getUpperBound());
            }

            if (oerElement.isFixedLength())
            {
                out.write(encoded);
            }
            else
            {
                encodeLength(encoded.length);
                out.write(encoded);
            }
            debugPrint(oerElement.appendLabel(""));
            out.flush();
            break;
        }

        case UTF8_STRING:
        {
            ASN1UTF8String utf8 = ASN1UTF8String.getInstance(encodable);
            byte[] encoded = Strings.toUTF8ByteArray(utf8.getString());
            encodeLength(encoded.length);
            out.write(encoded);
            debugPrint(oerElement.appendLabel(""));
            out.flush();
            break;
        }
        case BIT_STRING:
        {
            ASN1BitString bitString = ASN1BitString.getInstance(encodable);
            byte[] bytes = bitString.getBytes();
            if (oerElement.isFixedLength())
            {
                out.write(bytes);
                debugPrint(oerElement.appendLabel(oerElement.rangeExpression()));
            }
            else
            {
                int padBits = bitString.getPadBits();
                encodeLength(bytes.length + 1); // 13.3.1
                out.write(padBits); // 13.3.2
                out.write(bytes); // 13.3.3
                debugPrint(oerElement.appendLabel(oerElement.rangeExpression()));
            }
            out.flush();
        }
        break;
        case NULL:
            // Does not encode in OER.
            break;
        case EXTENSION:
        {
            ASN1OctetString octets = ASN1OctetString.getInstance(encodable);
            byte[] bytes = octets.getOctets();
            if (oerElement.isFixedLength())
            {
                out.write(bytes);
            }
            else
            {
                encodeLength(bytes.length);
                out.write(bytes);
            }
            debugPrint(oerElement.appendLabel(oerElement.rangeExpression()));
            out.flush();
            break;
        }

        case ENUM_ITEM:
            // Used to define options does not encode.
            break;
        case BOOLEAN:
            debugPrint(oerElement.getLabel());
            ASN1Boolean asn1Boolean = ASN1Boolean.getInstance(encodable);
            if (asn1Boolean.isTrue())
            {
                out.write(255);
            }
            else
            {
                out.write(0);
            }
            out.flush();
        }

    }

    protected void debugPrint(String what)
    {

        if (debugOutput != null)
        {

            StackTraceElement[] callStack = Thread.currentThread().getStackTrace();
            int level = -1;
            for (int i = 0; i != callStack.length; i++)
            {
                StackTraceElement ste = callStack[i];
                if (ste.getMethodName().equals("debugPrint"))
                {
                    level = 0;
                    continue;
                }
                if (ste.getClassName().contains("OERInput"))
                {
                    level++;
                }
            }

            for (; level > 0; level--)
            {
                debugOutput.append("    ");
            }
            debugOutput.append(what).append("\n");
            debugOutput.flush();
        }
    }

    private void encodeLength(long len)
        throws IOException
    {
        if (len <= 127) // complies with 31.2
        {
            out.write((int)len); // short form 8.6.3
        }
        else
        {
            // Long form,
            byte[] value = BigIntegers.asUnsignedByteArray(BigInteger.valueOf(len));
            out.write((value.length | 0x80));
            out.write(value);
        }
    }

    private void encodeQuantity(long quantity)
        throws IOException
    {
        byte[] quantityEncoded = BigIntegers.asUnsignedByteArray(BigInteger.valueOf(quantity));
        out.write(quantityEncoded.length);
        out.write(quantityEncoded);
    }

    public void write(int b)
        throws IOException
    {
        out.write(b);
    }


    public void writePlainType(ASN1Encodable value, Element e)
        throws IOException
    {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        OEROutputStream oerOutputStream = new OEROutputStream(bos);
        oerOutputStream.write(value, e);
        oerOutputStream.flush();
        oerOutputStream.close();

        encodeLength(bos.size());
        write(bos.toByteArray());
    }


}
