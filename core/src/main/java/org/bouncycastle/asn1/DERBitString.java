package org.bouncycastle.asn1;

import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;

import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.io.Streams;

/**
 * ASN.1 BIT STRING object.
 * <p>
 * The first byte contains the count of padding bits added on the tail of the byte array's last byte.
 * <p>
 * The bits are packed <i>big endian</i>, meaning first bit goes to highest bit of the octet (bit 8),
 * until a bit is put on bit 1, which completes the octet.
 * <p>
 * For example a 6 bit data ABCDEF will be encoded as: ABCDEF00, where 'A' goes to bit 8,
 * 'F' to bit 3, and padding zero to bits 2 and 1 (per X.690).
 * The padding count byte will have value 2 in it.
 * <p>
 * In normal usage with byte data inside BIT STRING the padding count is zero and every payload byte is filled.
 * <hr>
 * <h2>X.690</h2>
 * <h3>3: Definitions </h3>
 * <b>3.14</b> trailing 0 bit: A 0 in the last position of a bitstring value.
 * <blockquote>
 * NOTE &mdash; The 0 in a bitstring value consisting of a single 0 bit
 * is a trailing 0 bit. Its removal produces an empty bitstring.
 * </blockquote>
 *
 * <h3>8: Basic encoding rules</h3>
 * <h4>8.6 Encoding of a bitstring value</h4>
 * <b>8.6.1</b> The encoding of a bitstring value shall be either
 * primitive or constructed at the option of the sender.
 * <blockquote>
 * NOTE – Where it is necessary to transfer part of a bit string
 * before the entire bitstring is available, the constructed encoding is used.
 * </blockquote>
 * <p>
 * <b>8.6.2</b> The contents octets for the primitive encoding shall
 * contain an initial octet followed by zero, one or more subsequent octets.
 * <p>
 * <b>8.6.2.1</b> The bits in the bitstring value, commencing with the leading
 * bit and proceeding to the trailing bit, shall be placed in bits 8 to 1 of
 * the first subsequent octet, followed by bits 8 to 1 of the second subsequent octet,
 * followed by bits 8 to 1 of each octet in turn, followed by as many bits as are needed
 * of the final subsequent octet, commencing with bit 8.
 * <blockquote>
 * NOTE – The terms "leading bit" and "trailing bit" are defined in
 * ITU-T Rec. X.680 | ISO/IEC 8824-1, 21.2.
 * </blockquote>
 * <p>
 * <b>8.6.2.2</b> The initial octet shall encode, as an unsigned binary integer
 * with bit 1 as the least significant bit, the number of unused bits in the final
 * subsequent octet. The number shall be in the range zero to seven.
 * <p>
 * <b>8.6.2.3</b> If the bitstring is empty, there shall be no subsequent octets,
 * and the initial octet shall be zero.
 * <p>
 * <b>8.6.2.4</b> Where ITU-T Rec. X.680 | ISO/IEC 8824-1, 21.7, applies a BER encoder/decoder
 * can add or remove trailing 0 bits from the value.
 * <blockquote>
 * NOTE – If a bitstring value has no 1 bits, then an encoder
 * (as a sender's option) may encode the value with a length of 1 and with 
 * an initial octet set to 0 or may encode it as a bit string with
 * one or more 0 bits following the initial octet.
 * </blockquote>
 * <p>
 * <b>8.6.3</b> The contents octets for the constructed encoding shall
 * consist of zero, one, or more nested encodings.
 * <blockquote>
 * NOTE – Each such encoding includes identifier, length, and contents octets,
 * and may include end-of-contents octets if it is constructed.
 * </blockquote>
 * <p>
 * <b>8.6.4</b> To encode a bitstring value in this way, it is segmented.
 * Each segment shall consist of a series of consecutive bits of the value,
 * and with the possible exception of the last, shall contain a number of
 * bits which is a multiple of eight.Each bit in the overall value shall
 * be in precisely one segment, but there shall be no significance placed
 * on the segment boundaries.
 * <blockquote>
 * NOTE – A segment may be of size zero, i.e. contain no bits.
 * </blockquote>
 * <p>
 * <b>8.6.4.1</b> Each encoding in the contents octets shall represent
 * a segment of the overall bitstring, the encoding arising from a recursive
 * application of this subclause. In this recursive application,
 * each segment is treated as if it were a bitstring value.
 * The encodings of the segments shall appear in the contents octets
 * in the order in which their bits appear in the overall value.
 * <blockquote>
 * NOTE 1 – As a consequence of this recursion, each encoding in
 * the contents octets may itself be primitive or constructed. 
 * However, such encodings will usually be primitive.
 * <p>
 * NOTE 2 – In particular, the tags in the contents octets are always universal class, number 3.
 * </blockquote>
 * <b>8.6.4.2</b> Example (omitted)
 *
 * <h3>9: Canonical encoding rules </h3>
 * The encoding of a data values employed by the canonical encoding rules
 * is the basic encoding described in clause 8, 
 * together with the following restrictions and those also listed in clause 11.
 * <h4>9.1 Length forms</h4>
 * If the encoding is constructed, it shall employ the indefinite length form.
 * If the encoding is primitive, it shall include the fewest length octets necessary.
 * [Contrast with 8.1.3.2 b).]
 * <h4>9.2 String encoding forms</h4>
 * Bitstring, octetstring, and restricted character string values
 * shall be encoded with a primitive encoding if they would 
 * require no more than 1000 contents octets, and as a constructed
 * encoding otherwise.
 * The string fragments contained in the constructed encoding shall
 * be encoded with a primitive encoding.
 * The encoding of each fragment, except possibly the last,
 * shall have 1000 contents octets. (Contrast with 8.21.6.)
 *
 * <h3>10: Distinguished encoding rules</h3>
 * The encoding of a data values employed by
 * the distinguished encoding rules is
 * the basic encoding described in clause 8, 
 * together with the following restrictions
 * and those also listed in clause 11. 
 * <h4>10.1 Length forms </h4>
 * The definite form of length encoding shall be used,
 * encoded in the minimum number of octets.
 * [Contrast with 8.1.3.2 b).] 
 * <h4>10.2 String encoding forms</h4>
 * For bitstring, octetstring and restricted character string types,
 * the constructed form of encoding shall not be used. (Contrast with 8.21.6.) 
 *
 * <h3>11: Restrictions on BER employed by both CER and DER</h3>
 * <h4>11.2 Unused bits</h4>
 * <b>11.2.1</b> Each unused bit in the final octet of
 * the encoding of a bit string value shall be set to zero.
 * <p>
 * <b>11.2.2</b> Where ITU-T Rec. X.680 | ISO/IEC 8824-1, 21.7, applies,
 * the bitstring shall have all trailing 0 bits removed before it is encoded.
 * <blockquote>
 * NOTE 1 &mdash; In the case where a size constraint has been applied,
 * the abstract value delivered by a decoder to the application will be 
 * one of those satisfying the size constraint and differing from
 * the transmitted value only in the number of trailing 0 bits.
 * <p>
 * NOTE 2 &mdash; If a bitstring value has no 1 bits,
 * then an encoder shall encode the value with a length of
 * 1 and an initial octet set to 0.
 * </blockquote>
 */

public class DERBitString
    extends ASN1Primitive
    implements ASN1String
{
    private static final char[]  table = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };
    
    protected byte[]      data;
    protected int         padBits;

    /**
     * Return the correct number of pad bits for a bit string defined in
     * a 32 bit constant
     */
    static protected int getPadBits(
        int bitString)
    {
        int val = 0;
        for (int i = 3; i >= 0; i--) 
        {
            //
            // this may look a little odd, but if it isn't done like this pre jdk1.2
            // JVM's break!
            //
            if (i != 0)
            {
                if ((bitString >> (i * 8)) != 0) 
                {
                    val = (bitString >> (i * 8)) & 0xFF;
                    break;
                }
            }
            else
            {
                if (bitString != 0)
                {
                    val = bitString & 0xFF;
                    break;
                }
            }
        }
 
        if (val == 0)
        {
            return 7;
        }


        int bits = 1;

        while (((val <<= 1) & 0xFF) != 0)
        {
            bits++;
        }

        return 8 - bits;
    }

    /**
     * Return the correct number of bytes for a bit string defined in
     * a 32 bit constant
     */
    static protected byte[] getBytes(int bitString)
    {
        int bytes = 4;
        for (int i = 3; i >= 1; i--)
        {
            if ((bitString & (0xFF << (i * 8))) != 0)
            {
                break;
            }
            bytes--;
        }
        
        byte[] result = new byte[bytes];
        for (int i = 0; i < bytes; i++)
        {
            result[i] = (byte) ((bitString >> (i * 8)) & 0xFF);
        }

        return result;
    }

    /**
     * Return a DERBitString from the passed in object
     * <p>
     * Accepted inputs:
     * <ul>
     * <li> null &rarr; null
     * <li> {@link DERBitString} object
     * </ul>
     * <p>
     * Note: Does NOT accept byte[]!
     *
     * @param obj object to be converted.
     * @return converted value.
     * @exception IllegalArgumentException if the object cannot be converted.
     */
    public static DERBitString getInstance(
        Object  obj)
    {
        if (obj == null || obj instanceof DERBitString)
        {
            return (DERBitString)obj;
        }

        throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
    }

    /**
     * Return a Bit String from a tagged object.
     *
     * @param obj the tagged object holding the object we want
     * @param explicit true if the object is meant to be explicitly
     *              tagged false otherwise.
     * @exception IllegalArgumentException if the tagged object cannot
     *               be converted.
     */
    public static DERBitString getInstance(
        ASN1TaggedObject obj,
        boolean          explicit)
    {
        ASN1Primitive o = obj.getObject();

        if (explicit || o instanceof DERBitString)
        {
            return getInstance(o);
        }
        else
        {
            return fromOctetString(((ASN1OctetString)o).getOctets());
        }
    }
    
    protected DERBitString(
        byte    data,
        int     padBits)
    {
        this.data = new byte[1];
        this.data[0] = data;
        this.padBits = padBits;
    }

    /**
     * Construct a DERBitString from 'data' bytes with 'padBits'
     * telling number of padding bits on last byte.
     *
     * @param data the octets making up the bit string.
     * @param padBits the number of extra bits at the end of the string.
     */
    public DERBitString(
        byte[]  data,
        int     padBits)
    {
        this.data = data;
        this.padBits = padBits;
    }

    /**
     * Construct a DERBitString from 'data' bytes that are byte aligned,
     * and therefore the padding will be zero.
     */
    public DERBitString(
        byte[]  data)
    {
        this(data, 0);
    }

    /**
     * Construct a DERBitString from an 'int' value.
     */
    public DERBitString(
        int value)
    {
        this.data = getBytes(value);
        this.padBits = getPadBits(value);
    }

    public DERBitString(
        ASN1Encodable obj)
        throws IOException
    {
        this.data = obj.toASN1Primitive().getEncoded(ASN1Encoding.DER);
        this.padBits = 0;
    }

    /**
     * Get raw byte[] vector of the underlying value
     */
    public byte[] getBytes()
    {
        return data;
    }

    /**
     * Get padding bit count.
     */
    public int getPadBits()
    {
        return padBits;
    }


    /**
     * @return the value of the bit string as an int (truncating if necessary)
     */
    public int intValue()
    {
        int value = 0;
        
        for (int i = 0; i != data.length && i != 4; i++)
        {
            value |= (data[i] & 0xff) << (8 * i);
        }
        
        return value;
    }

    @Override
    boolean isConstructed()
    {
        return false;
    }

    @Override
    int encodedLength()
    {
        return 1 + StreamUtil.calculateBodyLength(data.length + 1) + data.length + 1;
    }

    @Override
    void encode(
        ASN1OutputStream  out)
        throws IOException
    {
        byte[]  bytes = new byte[getBytes().length + 1];

        bytes[0] = (byte)getPadBits();
        System.arraycopy(getBytes(), 0, bytes, 1, bytes.length - 1);

        out.writeEncoded(BERTags.BIT_STRING, bytes);
    }

    @Override
    public int hashCode()
    {
        return padBits ^ Arrays.hashCode(data);
    }

    @Override
    protected boolean asn1Equals(
        ASN1Primitive  o)
    {
        if (!(o instanceof DERBitString))
        {
            return false;
        }

        DERBitString other = (DERBitString)o;

        return this.padBits == other.padBits
            && Arrays.areEqual(this.data, other.data);
    }

    public String getString()
    {
        StringBuffer          buf = new StringBuffer("#");
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ASN1OutputStream      aOut = new ASN1OutputStream(bOut);
        
        try
        {
            aOut.writeObject(this);
        }
        catch (IOException e)
        {
           throw new RuntimeException("internal error encoding BitString");
        }
        
        byte[]    string = bOut.toByteArray();
        
        for (int i = 0; i != string.length; i++)
        {
            buf.append(table[(string[i] >>> 4) & 0xf]);
            buf.append(table[string[i] & 0xf]);
        }
        
        return buf.toString();
    }

    @Override
    public String toString()
    {
        return getString();
    }

    static DERBitString fromOctetString(byte[] bytes)
    {
        if (bytes.length < 1)
        {
            throw new IllegalArgumentException("truncated BIT STRING detected");
        }

        int padBits = bytes[0];
        byte[] data = new byte[bytes.length - 1];

        if (data.length != 0)
        {
            System.arraycopy(bytes, 1, data, 0, bytes.length - 1);
        }

        return new DERBitString(data, padBits);
    }

    static DERBitString fromInputStream(int length, InputStream stream)
        throws IOException
    {
        if (length < 1)
        {
            throw new IllegalArgumentException("truncated BIT STRING detected");
        }

        int padBits = stream.read();
        byte[] data = new byte[length - 1];

        if (data.length != 0)
        {
            if (Streams.readFully(stream, data) != data.length)
            {
                throw new EOFException("EOF encountered in middle of BIT STRING");
            }
        }

        return new DERBitString(data, padBits);
    }
}
