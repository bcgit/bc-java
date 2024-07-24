package org.bouncycastle.asn1.util;

import org.bouncycastle.asn1.*;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.util.Objects;

/**
 * Utility class for dumping ASN.1 objects as (hopefully) human friendly strings.
 */
public class ASN1Dump
{
    private static final String NL = System.lineSeparator();
    private static final String TAB = IndentingAppendable.TAB;
    private static final int SAMPLE_SIZE = 32;

    /**
     * dump a DER object as a formatted string with indentation
     *
     * @param obj the ASN1Primitive to be dumped out.
     */
    static void _dumpAsString(
        //String        indent,
        boolean       verbose,
        ASN1Primitive obj,
        IndentingAppendable    buf)
    {
        if (obj instanceof ASN1Null) {
            buf.appendIndentedLine("NULL");
        } else if (obj instanceof ASN1Sequence) {
            if (obj instanceof BERSequence) {
                buf.appendIndentedLine("BER Sequence");
            } else if (obj instanceof DERSequence) {
                buf.appendIndentedLine("DER Sequence");
            } else {
                buf.appendIndentedLine("Sequence");
            }

            final ASN1Sequence sequence = (ASN1Sequence) obj;

            buf.incrementIndentLevel();
            for (ASN1Encodable it : sequence) {
                _dumpAsString(verbose, it.toASN1Primitive(), buf);
            }
            buf.decrementIndentLevel();
        } else if (obj instanceof ASN1Set) {
            final String description;
            if (obj instanceof BERSet) {
                description = "BER Set";
            } else if (obj instanceof DERSet) {
                description = "DER Set";
            } else {
                description = "Set";
            }
            buf.appendIndentedLine(description);

            final ASN1Set set = (ASN1Set) obj;
            buf.incrementIndentLevel();
            for (int i = 0, count = set.size(); i < count; ++i) {
                _dumpAsString(verbose, set.getObjectAt(i).toASN1Primitive(), buf);
            }
            buf.decrementIndentLevel();
        } else if (obj instanceof ASN1TaggedObject) {
            buf.appendIndent();
            if (obj instanceof BERTaggedObject) {
                buf.append("BER Tagged ");
            } else if (obj instanceof DERTaggedObject) {
                buf.append("DER Tagged ");
            } else {
                buf.append("Tagged ");
            }

            final ASN1TaggedObject o = (ASN1TaggedObject) obj;
            buf.append(ASN1Util.getTagText(o));
            if (!o.isExplicit()) {
                buf.append(" IMPLICIT ");
            }
            buf.appendLine().incrementIndentLevel();
            _dumpAsString(verbose, o.getBaseObject().toASN1Primitive(), buf);
            buf.decrementIndentLevel();
        } else if (obj instanceof ASN1OctetString) {
            final ASN1OctetString oct = (ASN1OctetString) obj;
            if (obj instanceof BEROctetString) {
                buf.appendIndentedLine("BER Constructed Octet String[" + oct.getOctets().length + "]");
            } else {
                buf.appendIndentedLine("DER Octet String[" + oct.getOctets().length + "]");
            }
            if (verbose) {
                dumpBinaryDataAsString(buf, oct.getOctets());
            } else {
                buf.append(NL);
            }
        } else if (obj instanceof ASN1ObjectIdentifier) {
            buf.appendIndentedLine(toASN1String("ObjectIdentifier", ((ASN1ObjectIdentifier) obj).getId()));
        } else if (obj instanceof ASN1RelativeOID) {
            buf.appendIndentedLine(toASN1String("RelativeOID", ((ASN1RelativeOID) obj).getId()));
        } else if (obj instanceof ASN1Boolean) {
            buf.appendIndentedLine(toASN1String("Boolean", ((ASN1Boolean) obj).isTrue()));
        } else if (obj instanceof ASN1Integer) {
            buf.appendIndentedLine(toASN1String("Integer", ((ASN1Integer) obj).getValue()));
        } else if (obj instanceof ASN1BitString) {
            final ASN1BitString bitString = (ASN1BitString) obj;
            final String line;
            if (bitString instanceof DERBitString) {
                line = toASN1BitString("DER Bit String", bitString);
            } else if (bitString instanceof DLBitString) {
                line = toASN1BitString("DL Bit String", bitString);
            } else {
                line = toASN1BitString("BER Bit String", bitString);
            }
            buf.appendIndentedLine(line);

            if (verbose) {
                dumpBinaryDataAsString(buf, bitString.getBytes());
            } else {
                buf.appendLine();
            }
        } else if (obj instanceof ASN1IA5String) {
            buf.appendIndentedLine(toASN1String("IA5String", (ASN1IA5String) obj));
        } else if (obj instanceof ASN1UTF8String) {
            buf.appendIndentedLine(toASN1String("UTF8String", (ASN1UTF8String) obj));
        } else if (obj instanceof ASN1NumericString) {
            buf.appendIndentedLine(toASN1String("NumericString", (ASN1NumericString) obj));
        } else if (obj instanceof ASN1PrintableString) {
            buf.appendIndentedLine(toASN1String("PrintableString", (ASN1PrintableString) obj));
        } else if (obj instanceof ASN1VisibleString) {
            buf.appendIndentedLine(toASN1String("VisibleString", (ASN1VisibleString) obj));
        } else if (obj instanceof ASN1BMPString) {
            buf.appendIndentedLine(toASN1String("BMPString", (ASN1BMPString) obj));
        } else if (obj instanceof ASN1T61String) {
            buf.appendIndentedLine(toASN1String("T61String", (ASN1T61String) obj));
        } else if (obj instanceof ASN1GraphicString) {
            buf.appendIndentedLine(toASN1String("GraphicString", (ASN1GraphicString) obj));
        } else if (obj instanceof ASN1VideotexString) {
            buf.appendIndentedLine(toASN1String("VideotexString", (ASN1VideotexString) obj));
        } else if (obj instanceof ASN1UTCTime) {
            buf.appendIndentedLine(toASN1String("UTCTime", ((ASN1UTCTime) obj).getTime()));
        } else if (obj instanceof ASN1GeneralizedTime) {
            buf.appendIndentedLine(toASN1String("GeneralizedTime", ((ASN1GeneralizedTime) obj).getTime()));
        } else if (obj instanceof ASN1Enumerated) {
            final ASN1Enumerated en = (ASN1Enumerated) obj;
            buf.appendIndentedLine(toASN1String("DER Enumerated", String.valueOf(en.getValue())));
        } else if (obj instanceof ASN1ObjectDescriptor) {
            final ASN1ObjectDescriptor od = (ASN1ObjectDescriptor) obj;
            buf.appendIndentedLine(toASN1String("ObjectDescriptor", od.getBaseGraphicString()));
        } else if (obj instanceof ASN1External) {
            final ASN1External ext = (ASN1External) obj;
            buf.appendIndentedLine("External ")
               .incrementIndentLevel();
            if (ext.getDirectReference() != null) {
                buf.appendIndent().append("Direct Reference: ").appendLine(ext.getDirectReference().getId());
            }
            if (ext.getIndirectReference() != null) {
                buf.appendIndent().append("Indirect Reference: ").appendLine(String.valueOf(ext.getIndirectReference()));
            }
            if (ext.getDataValueDescriptor() != null) {
                _dumpAsString(verbose, ext.getDataValueDescriptor(), buf);
            }
            buf.appendIndent().append("Encoding: ").appendLine(String.valueOf(ext.getEncoding()));
            _dumpAsString(verbose, ext.getExternalContent(), buf);
        } else {
            buf.appendIndentedLine(String.valueOf(obj));
        }
    }

    static String toASN1String(String asn1TypeName, ASN1String str) {
        return toASN1String(asn1TypeName, str.getString());
    }

    static String toASN1String(String asn1TypeName, Object obj) {
        return toASN1String(asn1TypeName, String.valueOf(obj));
    }

    static String toASN1String(String asn1TypeName, String str) {
        return asn1TypeName + '(' + str + ')';
    }

    static String toASN1BitString(String asn1TypeName, ASN1BitString asn1BitString) {
        return asn1TypeName + "[" + asn1BitString.getBytes().length + ", " + asn1BitString.getPadBits() + "] ";
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
        final ASN1Primitive primitive;
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

        final IndentingAppendable buf = new IndentingAppendable();
        _dumpAsString(verbose, primitive, buf);
        return buf.toString();
    }

    private static void dumpBinaryDataAsString(IndentingAppendable buf, byte[] bytes)
    {
        buf.incrementIndentLevel().appendLine();
        for (int i = 0; i < bytes.length; i += SAMPLE_SIZE)
        {
            buf.appendIndent();
            if (bytes.length - i > SAMPLE_SIZE)
            {
                buf.append(Strings.fromByteArray(Hex.encode(bytes, i, SAMPLE_SIZE)))
                   .appendIndentedLine(calculateAscString(bytes, i, SAMPLE_SIZE));
            }
            else
            {
                buf.append(Strings.fromByteArray(Hex.encode(bytes, i, bytes.length - i)));
                for (int j = bytes.length - i; j != SAMPLE_SIZE; j++)
                {
                    buf.append("  ");
                }
                buf.appendIndentedLine(calculateAscString(bytes, i, bytes.length - i));
            }
        }
        buf.decrementIndentLevel();
    }

    private static String calculateAscString(byte[] bytes, int off, int len) {
        final StringBuilder buf = new StringBuilder(len);
        for (int i = off; i != off + len; i++) {
            final byte b = bytes[i];
            if (b >= ' ' && b <= '~') {
                buf.append((char) b);
            }
        }
        return buf.toString();
    }

    static class IndentingAppendable implements Appendable {

        public static final String TAB = "    ";
        private static final String NL = System.lineSeparator();

        private final String indentWith;
        private final Appendable baseAppendable;

        private int indentLevel;
        private String indent;

        public IndentingAppendable() {
            this(new StringBuilder(), TAB);
        }

        public IndentingAppendable(String indentWith) {
            this(new StringBuilder(), indentWith);
        }

        public IndentingAppendable(Appendable baseAppendable) {
            this(baseAppendable, TAB);
        }

        private IndentingAppendable(Appendable baseAppendable, String indentWith) {
            this.baseAppendable = Objects.requireNonNull(baseAppendable, "base appendable");
            this.indentWith = Objects.requireNonNull(indentWith, "indent string");
            this.indent = indentWith;
        }

        public IndentingAppendable incrementIndentLevel() {
            this.indentLevel++;
            this.indent = repeat(indentWith, indentLevel);
            return this;
        }

        public IndentingAppendable decrementIndentLevel() {
            if (this.indentLevel > 0)
                this.indentLevel--;
            this.indent = repeat(indentWith, indentLevel);
            return this;
        }

        public int getIndentLevel(){
            return indentLevel;
        }

        static String repeat(String base, int times) {
            Objects.requireNonNull(base, "repeated string");
            if (times < 0)
                throw new IllegalArgumentException("times is negative: " + times);
            final int len = base.length();
            if (len == 1)
                return base;
            if (Integer.MAX_VALUE / times > len)
                throw new OutOfMemoryError("Required length exceeds implementation limit");
            char[] toRepeat = base.toCharArray();
            char[] repeated = new char[len * times];
            final int strLen = base.length();
            for (int i = 0; i < times - 1; i++) {
                final int from = i * strLen;
                System.arraycopy(toRepeat, 0, repeated, from, strLen);
            }
            return new String(repeated).intern();
        }

        @Override
        public IndentingAppendable append(CharSequence csq) {
            try {
                baseAppendable.append(csq);
                return this;
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }
        }

        @Override
        public IndentingAppendable append(CharSequence csq, int start, int end) {
            try {
                baseAppendable.append(csq, start, end);
                return this;
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }
        }

        @Override
        public IndentingAppendable append(char c) {
            try {
                baseAppendable.append(c);
                return this;
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }
        }

        public IndentingAppendable appendIndent() {
            return append(indent);
        }

        public IndentingAppendable appendLine(CharSequence csq) {
            return append(csq).appendLine();
        }

        public IndentingAppendable appendLine() {
            return append(NL);
        }

        public IndentingAppendable appendIndentedLine(CharSequence csq) {
            return appendIndent().appendLine(csq);
        }

        @Override
        public String toString() {
            return baseAppendable.toString();
        }
    }
}
