package org.bouncycastle.oer;


import java.io.ByteArrayInputStream;
import java.io.EOFException;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.util.Iterator;
import java.util.List;

import org.bouncycastle.asn1.ASN1Boolean;
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
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.io.Streams;

public class OERInputStream
    extends FilterInputStream
{

    private static final int[] bits = new int[]{1, 2, 4, 8, 16, 32, 64, 128};
    private static final int[] bitsR = new int[]{128, 64, 32, 16, 8, 4, 2, 1};
    protected PrintWriter debugOutput = null;
    private int maxByteAllocation = 1024 * 1024;
    protected PrintWriter debugStream = null;


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

    /**
     * Decode byte array.
     *
     * @param src     The src
     * @param element The definition
     * @return Asn1Encodable instance
     * @throws IOException
     */
    public static ASN1Encodable parse(byte[] src, Element element)
        throws IOException
    {
        OERInputStream in = new OERInputStream(new ByteArrayInputStream(src));
        return in.parse(element);
    }


    private int countOptionalChildTypes(Element element)
    {
        int optionalElements = 0;
        for (Iterator it = element.getChildren().iterator(); it.hasNext(); )
        {
            Element e = (Element)it.next();

            optionalElements += e.isExplicit() ? 0 : 1;
        }
        return optionalElements;
    }

    public ASN1Object parse(Element element)
        throws IOException
    {


        switch (element.getBaseType())
        {

        case OPAQUE:
            ElementSupplier es = element.resolveSupplier();
            return parse(new Element(es.build(), element));

        case Switch:
            throw new IllegalStateException("A switch element should only be found within a sequence.");

        case Supplier:
            return parse(new Element(element.getElementSupplier().build(), element));

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


            debugPrint(element + ("(len = " + j + ")"));

            ASN1EncodableVector avec = new ASN1EncodableVector();

            if (element.getChildren().get(0).getaSwitch() != null)
            {
                throw new IllegalStateException("element def for item in SEQ OF has a switch, switches only supported in sequences");
            }

            for (int n = 0; n < j; n++)
            {
                Element def = Element.expandDeferredDefinition(element.getChildren().get(0), element);
                avec.add(parse(def));
            }
            return new DERSequence(avec);
        }

        case SEQ:
        {
            Sequence sequence = new Sequence(in, element);//  sequence(countOptionalChildTypes(element), element.hasDefaultChildren(), element.isExtensionsInDefinition());
            debugPrint(element + (sequence.toString()));
            ASN1EncodableVector avec = new ASN1EncodableVector();
            List<Element> children = element.getChildren();
            int t = 0;

            //
            // Read root block of sequence.
            //
            int optionalPos = 0;
            for (t = 0; t < children.size(); t++)
            {
                Element child = children.get(t);

                if (child.getBaseType() == OERDefinition.BaseType.EXTENSION)
                {
                    // We don't encode these, they are marker when the possibility of an extension is indicated but no actual extensions
                    // are defined as yet.
                    continue;
                }

                if (child.getBlock() > 0)
                {
                    // We have exited the root block, so we need to break this loop.
                    break;
                }

                child = Element.expandDeferredDefinition(child, element);

                Element resolvedChild;
                if (child.getaSwitch() != null)
                {
                    resolvedChild = child.getaSwitch().result(new SwitchIndexer.Asn1EncodableVectorIndexer(avec));
                    if (resolvedChild.getParent() != element)
                    {
                        resolvedChild = new Element(resolvedChild, element);
                    }
                }
                else
                {
                    resolvedChild = child;
                }

                if (sequence.valuePresent == null)
                {
                    // Sequence with no optionals and no extensions defined.
                    avec.add(parse(resolvedChild));
                }
                else
                {

                    if (sequence.valuePresent[t])
                    {
                        if (resolvedChild.isExplicit())
                        {
                            avec.add(parse(resolvedChild));
                        }
                        else
                        {
                            // Optional and present
                            avec.add(OEROptional.getInstance(parse(resolvedChild)));
                        }
                    }
                    else
                    {
                        if (resolvedChild.getDefaultValue() != null)
                        {
                            avec.add(child.getDefaultValue());
                        }
                        else
                        {
                            avec.add(absent(child));
                        }
                    }
                }
            }

            //
            // We have and extension block
            //
            if (sequence.extensionFlagSet)
            {
                int l = readLength().intLength();
                byte[] rawPresenceList = allocateArray(l);
                if (Streams.readFully(in, rawPresenceList) != rawPresenceList.length)
                {
                    throw new IOException("did not fully read presence list.");
                }

                int presenceIndex = 8;
                int stop = rawPresenceList.length * 8 - rawPresenceList[0];


                for (; t < children.size() || presenceIndex < stop; t++)
                {
                    Element child = t < children.size() ? children.get(t) : null;

                    if (child == null)
                    {
                        // Extensions that we do not
                        // have a definition for need to be consumed and discarded.
                        if ((rawPresenceList[presenceIndex / 8] & bitsR[presenceIndex % 8]) != 0)
                        {
                            // skip.
                            int len = readLength().intLength();
                            while (--len >= 0)
                            {
                                in.read();
                            }


                        }
                    }
                    else
                    {
                        if (presenceIndex < stop &&
                            (rawPresenceList[presenceIndex / 8] & bitsR[presenceIndex % 8]) != 0)
                        {
                            avec.add(parseOpenType(child));
                        }
                        else
                        {
                            if (child.isExplicit())
                            {
                                throw new IOException("extension is marked as explicit but is not defined in presence list");
                            }
                            else
                            {
                                avec.add(OEROptional.ABSENT);
                            }
                        }
                    }
                    presenceIndex++;
                }
            }

            return new DERSequence(avec);
        }

        case CHOICE:
        {
            Choice choice = choice();
            debugPrint(choice.toString() + " " + choice.tag);
            if (choice.isContextSpecific())
            {
                Element choiceDef = Element.expandDeferredDefinition(element.getChildren().get(choice.getTag()), element);

                if (choiceDef.getBlock() > 0)
                {
                    debugPrint("Chosen (Ext): " + choiceDef);
                    return new DERTaggedObject(choice.tag, parseOpenType(choiceDef));
                }
                else
                {
                    debugPrint("Chosen: " + choiceDef);
                    return new DERTaggedObject(choice.tag, parse(choiceDef));
                }
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
                throw new IllegalStateException("Unimplemented tag type");
            }
            else
            {
                throw new IllegalStateException("Unimplemented tag type");
            }
        }
        case ENUM:
        {
            BigInteger bi = enumeration();
            debugPrint(element + ("ENUM(" + bi + ") = " + element.getChildren().get(bi.intValue()).getLabel()));
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

                if (bytesToRead < 0)
                {
                    bi = new BigInteger(data); // Twos compliment
                }
                else
                {
                    bi = BigIntegers.fromUnsignedByteArray(data);
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
                    bi = new BigInteger(1, data);
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
                debugPrint(element + ("INTEGER byteLen= " + data.length + " hex= " + bi.toString(16) + ")"));
            }

            return new ASN1Integer(bi);

        }
        case OCTET_STRING:
        {
            byte[] data;

            int readSize = 0;

            if (element.getUpperBound() != null && element.getUpperBound().equals(element.getLowerBound()))
            {
                // Fixed length there is no range.
                readSize = element.getUpperBound().intValue();
            }
            else
            {
                readSize = readLength().intLength();
            }

            data = allocateArray(readSize);


            if (Streams.readFully(this, data) != readSize)
            {
                throw new IOException("did not read all of " + element.getLabel());
            }

            if (debugOutput != null)
            {
                // -DM Hex.toHexString
                int l = Math.min(data.length, 32);
                debugPrint(element + ("OCTET STRING (" + data.length + ") = " + Hex.toHexString(data, 0, l) + " " + ((data.length > 32) ? "..." : "")));
            }

            return new DEROctetString(data);
        }
        case IA5String:
        {
            byte[] data;

            if (element.isFixedLength())
            {
                data = allocateArray(element.getUpperBound().intValue());
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
                debugPrint(element + ("UTF8 String (" + data.length + ") = " + content));
            }
            return new DERUTF8String(content);
        }
        case BIT_STRING:
        {
            byte[] data;

            if (element.isFixedLength())
            {
                data = new byte[element.getLowerBound().intValue() / 8];
            }
            else if (BigInteger.ZERO.compareTo(element.getUpperBound()) > 0)
            {
                // Fixed size.
                data = allocateArray(element.getUpperBound().intValue() / 8);
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
                debugPrint(element + (sb.toString()));
            }

            return new DERBitString(data);

        }
        case NULL:
            debugPrint(element + ("NULL"));
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
        case BOOLEAN:
            if (read() == 0)
            {
                return ASN1Boolean.FALSE;
            }
            return ASN1Boolean.TRUE;
        }


        throw new IllegalStateException("Unhandled type " + element.getBaseType());
    }

    private ASN1Encodable absent(Element child)
    {
        debugPrint(child + ("Absent"));
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
        throws IOException
    {
        int accumulator = 0;
        int byteVal = read();
        if (byteVal == -1)
        {
            throw new EOFException("expecting length");
        }

        if ((byteVal & 0x80) == 0) // short form 8.6.4
        {
            debugPrint("Len (Short form): " + (byteVal & 0x7F));
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

            // -DM Hex.toHexString
            debugPrint("Len (Long Form): " + (byteVal & 0x7F) + " actual len: " + Hex.toHexString(lengthInt));

            return new LengthInfo(BigIntegers.fromUnsignedByteArray(lengthInt), false);
        }

    }


    public BigInteger enumeration()
        throws IOException
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


    protected ASN1Encodable parseOpenType(Element e)
        throws IOException
    {
        int len = readLength().intLength();
        byte[] openTypeRaw = allocateArray(len);
        if (Streams.readFully(in, openTypeRaw) != openTypeRaw.length)
        {
            throw new IOException("did not fully read open type as raw bytes");
        }
        OERInputStream oerIn = null;
        try
        {
            ByteArrayInputStream bin = new ByteArrayInputStream(openTypeRaw);
            oerIn = new OERInputStream(bin);
            return oerIn.parse(e);
        }
        finally
        {
            if (oerIn != null)
            {
                oerIn.close();
            }
        }

    }


    public Choice choice()
        throws IOException
    {
        return new Choice(this);
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
            throws IOException
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
        private final int preamble;
        private final boolean[] valuePresent;
        private final boolean extensionFlagSet;

        public Sequence(InputStream src, Element element)
            throws IOException
        {
            super(src);
            if (element.hasPopulatedExtension() || element.getOptionals() > 0 || element.hasDefaultChildren())
            {
                preamble = in.read();
                if (preamble < 0)
                {
                    throw new EOFException("expecting preamble byte of sequence");
                }
                // We expect extensions AND the Extension bit (7) is set.
                extensionFlagSet = element.hasPopulatedExtension() && ((preamble & 0x80) == 0x80);
            }
            else
            {
                preamble = 0;
                extensionFlagSet = false;
                valuePresent = null;
                return;
            }

            valuePresent = new boolean[element.getChildren().size()];


            int block = 0;
            int j = element.hasPopulatedExtension() ? 6 /* After extension present bit */ : 7 /* no extension bit */;
            int mask = preamble;
            int presentIndex = 0;
            for (Element child : element.getChildren())
            {
                if (child.getBaseType() == OERDefinition.BaseType.EXTENSION)
                {
                    continue;
                }

                if (child.getBlock() != block)
                {
                    // Shifted into an extension block
                    // We need to exit here because we need to read content before picking up
                    // the extension block.
                    break;
                }

                if (child.isExplicit())
                {
                    valuePresent[presentIndex++] = true;
                }
                else
                {
                    // Optional.
                    if (j < 0)
                    {
                        mask = src.read();
                        if (mask < 0)
                        {
                            throw new EOFException("expecting mask byte sequence");
                        }
                        j = 7;
                    }
                    valuePresent[presentIndex++] = (mask & bits[j]) > 0;
                    j--;
                }

            }


        }




        public boolean hasOptional(int index)
        {
            return valuePresent[index];
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

            if (valuePresent == null)
            {
                sb.append("*");
            }
            else
            {
                for (int t = 0; t < valuePresent.length; t++)
                {
                    if (valuePresent[t])
                    {
                        sb.append("1");
                    }
                    else
                    {
                        sb.append("0");
                    }
                }
            }
            sb.append(")");
            return sb.toString();
        }

    }

    private static final class LengthInfo
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
            return BigIntegers.intValueExact(length);
        }
    }


}
