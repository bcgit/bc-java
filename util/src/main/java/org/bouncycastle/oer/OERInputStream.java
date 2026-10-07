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
    private int maxNestingDepth = 256;
    private int decodeDepth = 0;
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
        // Hard cap on recursion depth. The IEEE 1609.2 OER schema is cyclic (an Ieee1609Dot2Data can
        // nest inside its own SignedData payload) and the CHOICE tag / optional-present bits are
        // attacker-controlled, so without a bound a few KB of crafted input drives unbounded
        // recursive-descent parsing into a StackOverflowError before any signature check. The depth
        // is threaded into open-type sub-streams (parseOpenType) so the cycle through them counts too.
        if (decodeDepth >= maxNestingDepth)
        {
            throw new IOException("OER decoder exceeded maximum nesting depth of " + maxNestingDepth);
        }
        ++decodeDepth;
        try
        {
            return parseInternal(element);
        }
        finally
        {
            --decodeDepth;
        }
    }

    private ASN1Object parseInternal(Element element)
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
            // X.696 sec. 17.2: a variable-size unsigned number, which is one or more octets (3.7.12)
            if (l == 0)
            {
                throw new IOException("sequence-of quantity has zero length");
            }

            byte[] lenEnc = readBytes(l);

            //
            // The actual number of elements encoded into this seq-of.
            //
            int j = BigIntegers.fromUnsignedByteArray(lenEnc).intValue();

            // Every OER seq-of element occupies at least one byte, so a declared count larger than the
            // bytes left in the input is truncated or hostile. Bound it before the parse loop so a few
            // count bytes (e.g. a long-form 7F FF FF FF) cannot drive ~2^31 parse iterations and object
            // allocations before the per-element reads run out of input.
            if (j < 0 || j > available())
            {
                throw new IOException("SEQUENCE OF length " + j + " out of range");
            }

            debugPrint(element + ("(len = " + j + ")"));

            // a SEQUENCE OF has a single child, the component type, so it and its deferred expansion
            // are the same for every element
            Element component = element.getChildren().get(0);
            if (component.getaSwitch() != null)
            {
                throw new IllegalStateException("element def for item in SEQ OF has a switch, switches only supported in sequences");
            }
            Element def = Element.expandDeferredDefinition(component, element);

            // Limit pre-allocation according to a potentially-hostile input
            ASN1EncodableVector avec = new ASN1EncodableVector(Math.min(16, j));
            for (int n = 0; n < j; n++)
            {
                avec.add(parse(def));
            }
            return new DERSequence(avec);
        }

        case SEQ:
        {
            Sequence sequence = new Sequence(in, element);//  sequence(countOptionalChildTypes(element), element.hasDefaultChildren(), element.isExtensionsInDefinition());
            debugPrint(element + (sequence.toString()));
            List<Element> children = element.getChildren();
            // at most one entry per defined child: the root components and the known extension
            // additions; presence bits beyond the definition add nothing
            ASN1EncodableVector avec = new ASN1EncodableVector(children.size());
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
                byte[] rawPresenceList = readBytes(l);

                // the first octet is the count of unused bits in the last one, so it must be there and
                // must be 0..7: absent, it indexed an empty array; sign-extended from 0x80..0xFF it
                // made stop overshoot and the bitmap reads below run off the end
                if (rawPresenceList.length < 1)
                {
                    throw new IOException("presence list is empty");
                }

                int unusedBits = rawPresenceList[0] & 0xFF;
                if (unusedBits > 7)
                {
                    throw new IOException("presence list declares " + unusedBits + " unused bits");
                }

                int presenceIndex = 8;
                int stop = rawPresenceList.length * 8 - unusedBits;

                // The extension additions the definition knows about, each against its presence bit;
                // a bitmap shorter than the definition means the trailing ones are absent.
                for (; t < children.size(); t++, presenceIndex++)
                {
                    Element child = children.get(t);

                    if (presenceIndex < stop && (rawPresenceList[presenceIndex / 8] & bitsR[presenceIndex % 8]) != 0)
                    {
                        avec.add(parseOpenType(child));
                    }
                    else if (child.isExplicit())
                    {
                        throw new IOException("extension is marked as explicit but is not defined in presence list");
                    }
                    else
                    {
                        avec.add(OEROptional.ABSENT);
                    }
                }

                // Any further presence bits are extension additions this definition does not know
                // about: the ones marked present carry an open type each, consumed and discarded.
                for (; presenceIndex < stop; presenceIndex++)
                {
                    if ((rawPresenceList[presenceIndex / 8] & bitsR[presenceIndex % 8]) != 0)
                    {
                        skipUnknownExtension(readLength().intLength());
                    }
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
                // the tag comes from the wire and indexes the schema's alternatives; X.696 sec. 8.7
                // makes an unknown alternative a decode error, not an IndexOutOfBoundsException
                if (choice.getTag() >= element.getChildren().size())
                {
                    throw new IOException("CHOICE tag " + choice.getTag() + " is not one of the "
                        + element.getChildren().size() + " alternatives");
                }

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
            else
            {
                // the tag class is two bits off the wire, so an unimplemented one is malformed input
                // rather than an inconsistent decoder state
                throw new IOException("Unimplemented tag type");
            }
        }
        case ENUM:
        {
            BigInteger bi = enumeration();
            if (debugOutput != null)
            {
                // the label lookup treats the wire value as a child index, so it can be out of range;
                // the other five debugPrint sites are already guarded, this one was building its
                // argument - and throwing IndexOutOfBoundsException - on the production path
                String label = bi.bitLength() < 32 && bi.intValue() < element.getChildren().size()
                    ? element.getChildren().get(bi.intValue()).getLabel()
                    : "<no such enumerand>";
                debugPrint(element + ("ENUM(" + bi + ") = " + label));
            }
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
                data = readBytes(Math.abs(bytesToRead));

                if (bytesToRead < 0)
                {
                    bi = new BigInteger(data); // Twos compliment
                }
                else
                {
                    bi = BigIntegers.fromUnsignedByteArray(data);
                }


            }
            else if (element.isLowerBoundNonNegative()) // X.696 sec. 10.3 e): INTEGER (n ... MAX), n >= 0, or an upper bound past 2^64 - 1
            {
                // X.696 sec. 10.3 e): a variable-size unsigned number, which is one or more octets (3.7.12)
                data = readBytes(readLength().intLength());
                if (data.length == 0)
                {
                    throw new IOException("INTEGER has zero length");
                }
                bi = new BigInteger(1, data);
            }
            else
            {

                //
                // Classic twos compliment.
                //
                // X.696 sec. 10.4 e): a variable-size signed number, which is one or more octets (3.7.11)
                data = readBytes(readLength().intLength());
                if (data.length == 0)
                {
                    throw new IOException("INTEGER has zero length");
                }
                bi = new BigInteger(data);
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

            if (element.isFixedLength())
            {
                // X.696 sec. 14.1: the octets alone, with no length determinant
                readSize = element.getLowerBound().intValue();
            }
            else
            {
                readSize = readLength().intLength();
            }

            data = readBytes(readSize);

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
                data = readBytes(element.getUpperBound().intValue());
            }
            else
            {
                // 27.3 and 27.4 a length determinant followed by a number of octets.
                data = readBytes(readLength().intLength());
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
            byte[] data = readBytes(readLength().intLength());
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
            int padBits;

            if (element.isFixedLength())
            {
                // X.696 sec. 13.2: the octets alone, with no length determinant; the size is in bits,
                // and the unused bits of the final octet are known from it
                int bits = element.getLowerBound().intValue();
                data = readBytes((bits + 7) / 8);
                padBits = data.length * 8 - bits;
            }
            else
            {
                // X.696 sec. 13.3: a length determinant covering an initial octet, which gives the
                // number of unused bits (0 to 7) in the final octet, and the octets of the value
                int length = readLength().intLength();
                if (length == 0)
                {
                    throw new IOException("BIT STRING has no initial octet");
                }
                padBits = read();
                if (padBits < 0)
                {
                    throw new EOFException("BIT STRING initial octet missing");
                }
                if (padBits > 7)
                {
                    throw new IOException("BIT STRING declares " + padBits + " unused bits");
                }
                data = readBytes(length - 1);
                if (data.length == 0 && padBits != 0)
                {
                    // 13.3.4: an empty value has an initial octet of 0
                    throw new IOException("empty BIT STRING declares " + padBits + " unused bits");
                }
            }
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

            // TODO Reframe as (new method) DERBitString.withContents (m.m. above).
            return new DERBitString(data, padBits);
        }
        case NULL:
            debugPrint(element + ("NULL"));
            return DERNull.INSTANCE;

        case EXTENSION:

            // Route through readBytes so the attacker-controlled open-type length is bounded by
            // maxByteAllocation and by what the stream actually delivers, like every other
            // length-driven read in this decoder; a raw new byte[len] here let a long-form length
            // (e.g. 84 7F FF FF FF) drive an immediate OutOfMemoryError.
            byte[] value = readBytes(readLength().intLength());

            // -DM Hex.toHexString
            debugPrint("ext " + value.length + " " + Hex.toHexString(value));
            return new DEROctetString(value);
        case BOOLEAN:
        {
            int b = read();
            if (b < 0)
            {
                throw new EOFException("expecting boolean value");
            }
            return b == 0 ? ASN1Boolean.FALSE : ASN1Boolean.TRUE;
        }
        }


        throw new IllegalStateException("Unhandled type " + element.getBaseType());
    }

    private ASN1Encodable absent(Element child)
    {
        debugPrint(child + ("Absent"));
        return OEROptional.ABSENT;
    }

    /**
     * Discard the body of an extension this decoder has no definition for.
     * <p>
     * The length is taken from the encoding and bounded only by 2^31-1. Consuming it one
     * {@code in.read()} at a time discarded the -1 that signals end of stream, so a declared
     * length with nothing behind it spun for as long as the length said - and with a single
     * presence bit set the parse then <em>returned normally</em>, so nothing recorded that it had
     * happened. Each known extension is parsed from its own bounded stream, so the slots are
     * independently exhaustible and the cost scales with the number of them.
     * <p>
     * Consume in bounded chunks and fail at the real end of input instead. The length itself is
     * not capped at {@code maxByteAllocation}: nothing is allocated from it, and an unknown
     * extension may legitimately be larger than the decoder's allocation ceiling - it just has to
     * actually be present in the stream.
     */
    private void skipUnknownExtension(int len)
        throws IOException
    {
        if (len < 0)
        {
            throw new IOException("unknown extension length is negative: " + len);
        }

        byte[] buf = new byte[Math.min(len, 4096)];
        while (len > 0)
        {
            int read = in.read(buf, 0, Math.min(len, buf.length));
            if (read < 0)
            {
                throw new EOFException("unknown extension truncated, " + len + " bytes not delivered");
            }
            len -= read;
        }
    }

    /**
     * Read exactly {@code len} bytes, the length having come from the encoding or the schema.
     * <p>
     * The length is capped at {@code maxByteAllocation}, and the read goes through
     * {@link Streams#readLenBytesFully(InputStream, int)}, which does not allocate the full
     * array until the stream has delivered a fair part of it - so a hostile length within the
     * cap, or a cap a caller has raised, cannot drive a large allocation from a short input,
     * and a stream that ends early fails with an {@link EOFException} rather than leaving a
     * zero-padded buffer to be decoded as a value.
     */
    private byte[] readBytes(int len)
        throws IOException
    {
        if (len > maxByteAllocation)
        {
            throw new IllegalArgumentException("required byte array size " + len + " was greater than " + maxByteAllocation);
        }
        return Streams.readLenBytesFully(this, len);
    }

    public BigInteger parseInt(boolean unsigned, int size)
        throws Exception
    {
        byte[] buf = Streams.readLenBytesFully(this, size);
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
        return parseInt(true, 8);
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
            // Long form 8.6.5: bits 7 to 1 give the number of subsequent octets, 1 to 127
            int octets = byteVal & 0x7F;
            if (octets == 0)
            {
                throw new IOException("length determinant long form has zero length");
            }

            byte[] lengthInt = Streams.readLenBytesFully(this, octets);

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
            // Long form, X.696 sec. 11.4: bits 7 to 1 give the number of subsequent octets, 1 to 127
            int l = first & 0x7f;
            if (l == 0)
            {
                throw new IOException("ENUMERATED long form has zero length");
            }
            byte[] buf = Streams.readLenBytesFully(this, l);

            // X.696 sec. 11.4: the long form carries the value as a two's-complement signed integer,
            // so a negative enumeration (a set top bit here) is a valid value and must stay negative.
            return new BigInteger(buf);
        }
        return BigInteger.valueOf(first);
    }


    protected ASN1Encodable parseOpenType(Element e)
        throws IOException
    {
        byte[] openTypeRaw = readBytes(readLength().intLength());
        OERInputStream oerIn = null;
        try
        {
            ByteArrayInputStream bin = new ByteArrayInputStream(openTypeRaw);
            oerIn = new OERInputStream(bin);
            // Carry the nesting budget across the open-type boundary so the Ieee1609Dot2Data/SignedData
            // cycle (which recurses through parseOpenType) cannot reset the depth guard each level.
            oerIn.maxNestingDepth = maxNestingDepth;
            oerIn.decodeDepth = decodeDepth;
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
                    // the continuation is only terminated by a clear bit 7, so without this the shift
                    // silently overflows and yields a negative tag
                    if (tag > (Integer.MAX_VALUE >> 7))
                    {
                        throw new IOException("CHOICE tag out of range");
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

    static final class LengthInfo
    {
        private final BigInteger length;
        private final boolean shortForm;

        public LengthInfo(BigInteger length, boolean shortForm)
        {
            this.length = length;
            this.shortForm = shortForm;
        }

        private int intLength()
            throws IOException
        {
            // the determinant is read as an unsigned big-endian value of up to 127 octets, so it can
            // exceed an int; intValueExact would leave an ArithmeticException to escape a decode API
            // that declares only IOException
            if (length.bitLength() > 31)
            {
                throw new IOException("length determinant out of range: " + length.bitLength() + " bits");
            }

            return length.intValue();
        }
    }


}
