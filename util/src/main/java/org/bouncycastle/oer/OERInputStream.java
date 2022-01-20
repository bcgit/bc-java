package org.bouncycastle.oer;


import java.io.EOFException;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.util.Iterator;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.Pack;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.io.Streams;

public class OERInputStream
    extends FilterInputStream
{

    private static final int[] bits = new int[]{1, 2, 4, 8, 16, 32, 64, 128};
    protected PrintWriter debugOutput = null;

//    public interface OERHandler
//    {
//        void handle(OERInputStream decoder)
//            throws Exception;
//    }
    private int maxByteAllocation = 1024 * 1024;

    /**
     * Root decoder of OER streaming data.
     * Maximum byte array allocation is 1Mb
     *
     * @param src source stream.
     */
    public OERInputStream(InputStream src)
    {
        super(src);
    }

    /**
     * Create an OER input and set the maximum byte array allocation size;
     *
     * @param src               The src.
     * @param maxByteAllocation the largest byte array that may eb allocated by this parser.
     */
    public OERInputStream(InputStream src, int maxByteAllocation)
    {
        super(src);
        this.maxByteAllocation = maxByteAllocation;
    }

    private int countOptionalChildTypes(OERDefinition.Element element)
    {
        int optionalElements = 0;
        for (Iterator it = element.children.iterator(); it.hasNext(); )
        {
            OERDefinition.Element e = (OERDefinition.Element)it.next();

            optionalElements += e.explicit ? 0 : 1;
        }
        return optionalElements;
    }

    public ASN1Object parse(OERDefinition.Element element)
        throws Exception
    {

        switch (element.baseType)
        {

        case Switch:
            throw new IllegalStateException("A switch element should only be found within a sequence.");

        case SEQ_OF:
        {
            int l = readLength().intLength();

            // This l is the number of bytes that holds the actual length of the sequence of.

            byte[] lenEnc = allocateArray(l);
            if (Streams.readFully(this, lenEnc) != lenEnc.length)
            {
                throw new IOException("could not read all of count of seq-of values");
            }

            //
            // The actual number of elements encoded into this seq-of.
            //
            int j = BigIntegers.fromUnsignedByteArray(lenEnc).intValue();


            debugPrint(element.appendLabel("(len = " + j + ")"));

            ASN1EncodableVector avec = new ASN1EncodableVector();

            if (element.children.get(0).aSwitch != null)
            {
                throw new IllegalStateException("element def for item in SEQ OF has a switch, switches only supported in sequences");
            }

            for (int n = 0; n < j; n++)
            {
                avec.add(parse(element.children.get(0)));
            }
            return new DERSequence(avec);
        }

        case SEQ:
        {
            Sequence sequence = sequence(countOptionalChildTypes(element), element.hasDefaultChildren(), element.extensionsInDefinition);
            debugPrint(element.appendLabel(sequence.toString()));

            ASN1EncodableVector avec = new ASN1EncodableVector();

            for (int t = 0; t < element.children.size(); t++)
            {
                OERDefinition.Element child = element.children.get(t);

                if (child.explicit)
                {
//                    debugPrint(child.appendLabel("E[" + t + "]"));

                    if (child.aSwitch != null)
                    {
                        child = child.aSwitch.result(new SwitchIndexer.Asn1EncodableVectorIndexer(avec));
                    }

                    avec.add(parse(child));
                }
                else
                {
                    if (sequence.hasOptional(element.optionalOrDefaultChildrenInOrder().indexOf(child)))
                    {
                        if (child.aSwitch != null)
                        {
                            child = child.aSwitch.result(new SwitchIndexer.Asn1EncodableVectorIndexer(avec));
                        }
                        //  debugPrint(child.appendLabel("O[" + t + "]"));
                        avec.add(OEROptional.getInstance(parse(child)));

                    }
                    else
                    {
                        if (child.aSwitch != null)
                        {
                            child = child.aSwitch.result(new SwitchIndexer.Asn1EncodableVectorIndexer(avec));
                        }

                        if (child.getDefaultValue() != null)
                        {
                            avec.add(child.defaultValue);
                            debugPrint("Using default.");
                        }
                        else
                        {
                            avec.add(absent(child));
                        }
                    }
                }

            }
            return new DERSequence(avec);
        }


        case CHOICE:
        {
            Choice choice = choice();
            debugPrint(element.appendLabel(choice.toString()));
            if (choice.isContextSpecific())
            {
                OERDefinition.Element item = element.children.get(choice.getTag());
                return new DERTaggedObject(choice.tag, parse(element.children.get(choice.getTag())));
            }
            else if (choice.isApplicationTagClass())
            {
                throw new IllegalStateException("Unimplemented tag type");
            }
            else if (choice.isPrivateTagClass())
            {
                throw new IllegalStateException("Unimplemented tag type");
            }
            else if (choice.isUniversalTagClass())
            {
                switch (choice.getTag())
                {

                }


            }
            else
            {
                throw new IllegalStateException("Unimplemented tag type");
            }
        }
        case ENUM:
        {
            BigInteger bi = enumeration();
            debugPrint(element.appendLabel("ENUM(" + bi + ") = " + element.children.get(bi.intValue()).label));
            return new ASN1Enumerated(bi);
        }
        case INT:
        {

            byte[] data;
            BigInteger bi;


            //
            // Special fixed width cases used for signed and unsigned 8/16/24/32/64 bit numbers.
            //
            int bytesToRead = element.intBytesForRange();
            if (bytesToRead != 0) // Fixed width
            {
                data = allocateArray(Math.abs(bytesToRead));
                Streams.readFully(this, data);
                switch (data.length)
                {
                case 1:
                    bi = BigInteger.valueOf(data[0]);
                    break;
                case 2:
                    bi = BigInteger.valueOf(Pack.bigEndianToShort(data, 0));
                    break;
                case 4:
                    bi = BigInteger.valueOf(Pack.bigEndianToInt(data, 0));
                    break;
                case 8:
                    bi = BigInteger.valueOf(Pack.bigEndianToLong(data, 0));
                    break;
                default:
                    throw new IllegalStateException("Unknown size");
                }


            }
            else if (element.isLowerRangeZero()) // INTEGER(0 ... MAX) or INTEGER (0 ... n)
            {
                LengthInfo lengthInfo = readLength();
                data = allocateArray(lengthInfo.intLength());
                Streams.readFully(this, data);
                if (data.length == 0)
                {
                    bi = BigInteger.ZERO;
                }
                else
                {
                    bi = BigIntegers.fromUnsignedByteArray(data);
                }
            }
            else
            {

                //
                // Classic twos compliment.
                //
                LengthInfo lengthInfo = readLength();
                data = allocateArray(lengthInfo.intLength());
                Streams.readFully(this, data);
                if (data.length == 0)
                {
                    bi = BigInteger.ZERO;
                }
                else
                {
                    bi = new BigInteger(data);
                }
            }


            if (debugOutput != null)
            {
                debugPrint(element.appendLabel("INTEGER(" + data.length + " " + bi.toString(16) + ")"));
            }

            return new ASN1Integer(bi);

        }
        case OCTET_STRING:
        {
            byte[] data;

            int readSize = 0;

            if (element.upperBound != null && element.upperBound.equals(element.lowerBound))
            {
                // Fixed length there is no range.
                readSize = element.upperBound.intValue();
            }
            else
            {
                readSize = readLength().intLength();
            }

            data = allocateArray(readSize);


            if (Streams.readFully(this, data) != readSize)
            {
                throw new IOException("did not read all of " + element.label);
            }

            if (debugOutput != null)
            {
                // -DM Hex.toHexString
                debugPrint(element.appendLabel("OCTET STRING (" + data.length + ") = " + Hex.toHexString(data, 0, Math.min(data.length, 32))));
            }

            return new DEROctetString(data);
        }
        case IA5String:
        {
            byte[] data;

            if (element.isFixedLength())
            {
                data = allocateArray(element.upperBound.intValue());
            }
            else
            {
                // 27.3 and 27.4 a length determinant followed by a number of octets.
                data = allocateArray(readLength().intLength());
            }

            if (Streams.readFully(this, data) != data.length)
            {
                throw new IOException("could not read all of IA5 string");
            }
            String content = Strings.fromByteArray(data);
            if (debugOutput != null)
            {
                debugPrint(element.appendLabel("IA5 String (" + data.length + ") = " + content));
            }
            return new DERIA5String(content);

        }

        case UTF8_STRING:
        {
            // 27.3 and 27.4 a length determinant followed by a number of octets.
            byte[] data = allocateArray(readLength().intLength());
            if (Streams.readFully(this, data) != data.length)
            {
                throw new IOException("could not read all of utf 8 string");
            }
            String content = Strings.fromUTF8ByteArray(data);
            if (debugOutput != null)
            {
                debugPrint(element.appendLabel("UTF8 String (" + data.length + ") = " + content));
            }
            return new DERUTF8String(content);
        }
        case BIT_STRING:
        {
            byte[] data;

            if (element.isFixedLength())
            {
                data = new byte[element.lowerBound.intValue() / 8];
            }
            else if (BigInteger.ZERO.compareTo(element.upperBound) > 0)
            {
                // Fixed size.
                data = allocateArray(element.upperBound.intValue() / 8);
            }
            else
            {
                // Length defined.
                data = allocateArray(readLength().intLength() / 8);
            }
            Streams.readFully(this, data);
            if (debugOutput != null)
            {
                StringBuffer sb = new StringBuffer();
                sb.append("BIT STRING(" + (data.length * 8) + ") = ");
                for (int i = 0; i != data.length; i++)
                {
                    byte b = data[i];
                    for (int t = 0; t < 8; t++)
                    {
                        sb.append((b & 0x80) > 0 ? "1" : "0");
                        b <<= 1;
                    }
                }
                debugPrint(element.appendLabel(sb.toString()));
            }

            return new DERBitString(data);

        }
        case NULL:
            debugPrint(element.appendLabel("NULL"));
            return DERNull.INSTANCE;

        case EXTENSION:

            LengthInfo li = readLength();
            byte[] value = new byte[li.intLength()];
            if (Streams.readFully(this, value) != li.intLength())
            {
                throw new IOException("could not read all of count of open value in choice (...) ");
            }

            // -DM Hex.toHexString
            debugPrint("ext " + li.intLength() + " " + Hex.toHexString(value));
            return new DEROctetString(value);
        }


        throw new IllegalStateException("Unhandled type " + element.baseType);
    }

    private ASN1Encodable absent(OERDefinition.Element child)
    {
        debugPrint(child.appendLabel("Absent"));
        return OEROptional.ABSENT;
    }

    private byte[] allocateArray(int requiredSize)
    {
        if (requiredSize > maxByteAllocation)
        {
            throw new IllegalArgumentException("required byte array size " + requiredSize + " was greater than " + maxByteAllocation);
        }
        return new byte[requiredSize];
    }

    public BigInteger parseInt(boolean unsigned, int size)
        throws Exception
    {
        byte[] buf = new byte[size];
        int read = Streams.readFully(this, buf);
        if (read != buf.length)
        {
            throw new IllegalStateException("integer not fully read");
        }
        return unsigned ? new BigInteger(1, buf) : new BigInteger(buf);

    }

    public BigInteger uint8()
        throws Exception
    {
        return parseInt(true, 1);
    }

    public BigInteger uint16()
        throws Exception
    {
        return parseInt(true, 2);
    }

    public BigInteger uint32()
        throws Exception
    {
        return parseInt(true, 4);
    }

    public BigInteger uint64()
        throws Exception
    {
        return parseInt(false, 8);
    }

    public BigInteger int8()
        throws Exception
    {
        return parseInt(false, 1);
    }

    public BigInteger int16()
        throws Exception
    {
        return parseInt(false, 2);
    }

    public BigInteger int32()
        throws Exception
    {
        return parseInt(false, 4);
    }

    public BigInteger int64()
        throws Exception
    {
        return parseInt(false, 8);
    }

    /**
     * Reads a length determinant deals with long ans short versions.
     *
     * @return
     * @throws Exception
     */
    public LengthInfo readLength()
        throws Exception
    {
        int accumulator = 0;
        int byteVal = read();
        if (byteVal == -1)
        {
            throw new EOFException("expecting length");
        }

        if ((byteVal & 0x80) == 0) // short form 8.6.4
        {
            return new LengthInfo(BigInteger.valueOf(byteVal & 0x7F), true);
        }
        else
        {
            // Long form 8.6.5

            byte[] lengthInt = new byte[(byteVal & 0x7F)];
            if (Streams.readFully(this, lengthInt) != lengthInt.length)
            {
                throw new EOFException("did not read all bytes of length definition");
            }

            return new LengthInfo(BigIntegers.fromUnsignedByteArray(lengthInt), false);
        }

    }


    public BigInteger enumeration()
        throws Exception
    {
        int first = read();
        if (first == -1)
        {
            throw new EOFException("expecting prefix of enumeration");
        }
        //
        // If the MSB is set then it is an extended enumeration, the trailing 7 bits are the number
        // of bytes in the encoding otherwise the value is the value of the byte.
        //
        if ((first & 0x80) == 0x80)
        {
            // Extended.
            int l = first & 0x7f;
            if (l == 0)
            {
                return BigInteger.ZERO;
            }
            byte[] buf = new byte[l];
            int i = Streams.readFully(this, buf);

            if (i != buf.length)
            {
                throw new EOFException("unable to fully read integer component of enumeration");
            }

            return new BigInteger(1, buf);
        }
        return BigInteger.valueOf(first);
    }


    public Sequence sequence(int expectedOptional, boolean hasOptionalChildren, boolean hasExtension)
        throws Exception
    {
        return new Sequence(this, expectedOptional, hasOptionalChildren, hasExtension);
    }

//    public OERInputStream sequence(int expectedOptional, boolean hasExtension, boolean hasOptionalChildren, OERHandler handler)
//        throws Exception
//    {
//        handler.handle(new Sequence(this, expectedOptional, hasOptionalChildren, hasExtension));
//        return this;
//    }

    public Choice choice()
        throws Exception
    {
        return new Choice(this);
    }

//    public OERInputStream choice(OERHandler handler)
//        throws Exception
//    {
//        handler.handle(new Choice(this));
//        return this;
//    }

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

    public static class Choice
        extends OERInputStream
    {

        final int preamble;
        final int tag;
        final int tagClass;

        /**
         * Root decoder of OER streaming data.
         *
         * @param src source stream.
         */
        public Choice(InputStream src)
            throws Exception
        {

            super(src);
            preamble = read();
            if (preamble < 0)
            {
                throw new EOFException("expecting preamble byte of choice");
            }

            tagClass = preamble & 0xc0;
            int tag = preamble & 0x3f;
            //
            // 8.7.2.2 and 8.7.2.3 if tag >=63 then subsequent octets contain the remaining bits
            // of the tag. If the octet has bit 7 set then there is another octet to follow.
            //
            if (tag >= 63)
            {
                tag = 0;
                int part = 0;
                do
                {
                    part = src.read();
                    if (part < 0)
                    {
                        throw new EOFException("expecting further tag bytes");
                    }
                    tag <<= 7;
                    tag |= part & 0x7f;
                }
                while ((part & 0x80) != 0);

            }

            this.tag = tag;
        }

        public String toString()
        {
            StringBuilder sb = new StringBuilder();
            sb.append("CHOICE(");
            switch (tagClass)
            {
            case 0:
                sb.append("Universal ");
                break;
            case 0x40:
                sb.append("Application ");
                break;
            case 0xc0:
                sb.append("Private ");
                break;
            case 0x80:
                sb.append("ContextSpecific ");
                break;
            }
            sb.append("Tag = " + tag);
            sb.append(")");
            return sb.toString();
        }

        public int getTagClass()
        {
            return tagClass;
        }

        public int getTag()
        {
            return tag;
        }

        public boolean isContextSpecific()
        {
            return tagClass == 0x80;
        }

        public boolean isUniversalTagClass()
        {
            return tagClass == 0;
        }

        public boolean isApplicationTagClass()
        {
            return tagClass == 0x40;
        }

        public boolean isPrivateTagClass()
        {
            return tagClass == 0xc0;
        }

    }

    /**
     * OER sequence decoder, decodes prefix and determines which optional
     * parts are available.
     */
    public static class Sequence
        extends OERInputStream
    {
        final int preamble;
        private final boolean[] optionalPresent;
        private final boolean extensionFlagSet;

        public Sequence(InputStream src, int expectedOptional, boolean hasDefaults, boolean extension)
            throws IOException
        {
            super(src);


            if (expectedOptional == 0 && !extension && !hasDefaults)
            {
                preamble = 0;
                optionalPresent = new boolean[0];
                extensionFlagSet = false;
                return;
            }


            preamble = src.read();
            if (preamble < 0)
            {
                throw new EOFException("expecting preamble byte of sequence");
            }

            // We expect extensions AND the Extension bit (7) is set.
            extensionFlagSet = extension && ((preamble & 0x80) == 0x80);

            //
            // Load a boolean array, where true = optional is present otherwise false.
            // This is done by inspecting a sequence of bits starting from bit 6 if we expect extension or 7 if we do not
            // of the preamble
            // and testing the subsequent expectedOptional number of bits.
            int j = extension ? 6 : 7;
            optionalPresent = new boolean[expectedOptional];
            int mask = preamble;
            for (int t = 0; t < optionalPresent.length; t++)
            {
                if (j < 0)
                {
                    mask = src.read();
                    if (mask < 0)
                    {
                        throw new EOFException("expecting mask byte sequence");
                    }
                    j = 7;
                }
                optionalPresent[t] = (mask & bits[j]) > 0;
                j--;
            }

        }

        public boolean hasOptional(int index)
        {
            return optionalPresent[index];
        }

        public boolean hasExtension()
        {
            return extensionFlagSet;
        }


        public String toString()
        {
            StringBuilder sb = new StringBuilder();
            sb.append("SEQ(");
            sb.append(hasExtension() ? "Ext " : "");
            for (int t = 0; t < optionalPresent.length; t++)
            {
                if (optionalPresent[t])
                {
                    sb.append("1");
                }
                else
                {
                    sb.append("0");
                }
            }
            sb.append(")");
            return sb.toString();
        }

    }

    private final class LengthInfo
    {
        private final BigInteger length;
        private final boolean shortForm;

        public LengthInfo(BigInteger length, boolean shortForm)
        {
            this.length = length;
            this.shortForm = shortForm;
        }

        private int intLength()
        {
            return length.intValue();
        }
    }


}
