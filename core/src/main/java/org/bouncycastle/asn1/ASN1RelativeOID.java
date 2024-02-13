package org.bouncycastle.asn1;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;

import org.bouncycastle.util.Arrays;

public class ASN1RelativeOID
    extends ASN1Primitive
{
    static final ASN1UniversalType TYPE = new ASN1UniversalType(ASN1RelativeOID.class, BERTags.RELATIVE_OID)
    {
        ASN1Primitive fromImplicitPrimitive(DEROctetString octetString)
        {
            return createPrimitive(octetString.getOctets(), false);
        }
    };

    public static ASN1RelativeOID fromContents(byte[] contents)
    {
        if (contents == null)
        {
            throw new NullPointerException("'contents' cannot be null");
        }

        return createPrimitive(contents, true);
    }

    public static ASN1RelativeOID getInstance(Object obj)
    {
        if (obj == null || obj instanceof ASN1RelativeOID)
        {
            return (ASN1RelativeOID)obj;
        }
        if (obj instanceof ASN1Encodable)
        {
            ASN1Primitive primitive = ((ASN1Encodable)obj).toASN1Primitive();
            if (primitive instanceof ASN1RelativeOID)
            {
                return (ASN1RelativeOID)primitive;
            }
        }
        else if (obj instanceof byte[])
        {
            byte[] enc = (byte[])obj;
            try
            {
                return (ASN1RelativeOID)TYPE.fromByteArray(enc);
            }
            catch (IOException e)
            {
                throw new IllegalArgumentException("failed to construct relative OID from byte[]: " + e.getMessage());
            }
        }

        throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
    }

    public static ASN1RelativeOID getInstance(ASN1TaggedObject taggedObject, boolean explicit)
    {
        return (ASN1RelativeOID)TYPE.getContextInstance(taggedObject, explicit);
    }

    public static ASN1RelativeOID tryFromID(String identifier)
    {
        if (identifier == null)
        {
            throw new NullPointerException("'identifier' cannot be null");
        }
        if (!isValidIdentifier(identifier, 0))
        {
            return null;
        }

        return new ASN1RelativeOID(parseIdentifier(identifier), identifier);
    }

    private static final long LONG_LIMIT = (Long.MAX_VALUE >> 7) - 0x7F;

    private final byte[] contents;
    private String identifier;

    public ASN1RelativeOID(String identifier)
    {
        if (identifier == null)
        {
            throw new NullPointerException("'identifier' cannot be null");
        }
        if (!isValidIdentifier(identifier, 0))
        {
            throw new IllegalArgumentException("string " + identifier + " not a relative OID");
        }

        this.contents = parseIdentifier(identifier);
        this.identifier = identifier;        
    }

    private ASN1RelativeOID(ASN1RelativeOID oid, String branchID)
    {
        if (!isValidIdentifier(branchID, 0))
        {
            throw new IllegalArgumentException("string " + branchID + " not a valid relative OID branch");
        }

        this.contents = Arrays.concatenate(oid.contents, parseIdentifier(branchID));
        this.identifier = oid.getId() + "." + branchID;
    }

    private ASN1RelativeOID(byte[] contents, boolean clone)
    {
        if (!isValidContents(contents))
            throw new IllegalArgumentException("invalid relative OID contents");

        this.contents = clone ? Arrays.clone(contents) : contents;
        this.identifier = null;
    }

    private ASN1RelativeOID(byte[] contents, String identifier)
    {
        this.contents = contents;
        this.identifier = identifier;
    }

    public ASN1RelativeOID branch(String branchID)
    {
        return new ASN1RelativeOID(this, branchID);
    }

    public synchronized String getId()
    {
        if (identifier == null)
        {
            identifier = parseContents(contents);
        }

        return identifier;
    }

    public int hashCode()
    {
        return Arrays.hashCode(contents);
    }

    public String toString()
    {
        return getId();
    }

    boolean asn1Equals(ASN1Primitive other)
    {
        if (this == other)
        {
            return true;
        }
        if (!(other instanceof ASN1RelativeOID))
        {
            return false;
        }

        ASN1RelativeOID that = (ASN1RelativeOID)other;

        return Arrays.areEqual(this.contents, that.contents);
    }

    int encodedLength(boolean withTag)
    {
        return ASN1OutputStream.getLengthOfEncodingDL(withTag, contents.length);
    }

    void encode(ASN1OutputStream out, boolean withTag) throws IOException
    {
        out.writeEncodingDL(withTag, BERTags.RELATIVE_OID, contents);
    }

    boolean encodeConstructed()
    {
        return false;
    }

    static ASN1RelativeOID createPrimitive(byte[] contents, boolean clone)
    {
        return new ASN1RelativeOID(contents, clone);
    }

    static boolean isValidContents(byte[] contents)
    {
        if (contents.length < 1)
        {
            return false;
        }

        boolean subIDStart = true;
        for (int i = 0; i < contents.length; ++i)
        {
            if (subIDStart && (contents[i] & 0xff) == 0x80)
                return false;

            subIDStart = (contents[i] & 0x80) == 0;
        }

        return subIDStart;
    }

    static boolean isValidIdentifier(String identifier, int from)
    {
        int digitCount = 0;

        int pos = identifier.length();
        while (--pos >= from)
        {
            char ch = identifier.charAt(pos);

            if (ch == '.')
            {
                if (0 == digitCount || (digitCount > 1 && identifier.charAt(pos + 1) == '0'))
                {
                    return false;
                }

                digitCount = 0;
            }
            else if ('0' <= ch && ch <= '9')
            {
                ++digitCount;
            }
            else
            {
                return false;
            }
        }

        if (0 == digitCount || (digitCount > 1 && identifier.charAt(pos + 1) == '0'))
        {
            return false;
        }

        return true;
    }

    static String parseContents(byte[] contents)
    {
        StringBuffer objId = new StringBuffer();
        long value = 0;
        BigInteger bigValue = null;
        boolean first = true;

        for (int i = 0; i != contents.length; i++)
        {
            int b = contents[i] & 0xff;

            if (value <= LONG_LIMIT)
            {
                value += b & 0x7F;
                if ((b & 0x80) == 0)
                {
                    if (first)
                    {
                        first = false;
                    }
                    else
                    {
                        objId.append('.');
                    }

                    objId.append(value);
                    value = 0;
                }
                else
                {
                    value <<= 7;
                }
            }
            else
            {
                if (bigValue == null)
                {
                    bigValue = BigInteger.valueOf(value);
                }
                bigValue = bigValue.or(BigInteger.valueOf(b & 0x7F));
                if ((b & 0x80) == 0)
                {
                    if (first)
                    {
                        first = false;
                    }
                    else
                    {
                        objId.append('.');
                    }

                    objId.append(bigValue);
                    bigValue = null;
                    value = 0;
                }
                else
                {
                    bigValue = bigValue.shiftLeft(7);
                }
            }
        }

        return objId.toString();
    }

    static byte[] parseIdentifier(String identifier)
    {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        OIDTokenizer tok = new OIDTokenizer(identifier);
        while (tok.hasMoreTokens())
        {
            String token = tok.nextToken();
            if (token.length() <= 18)
            {
                writeField(bOut, Long.parseLong(token));
            }
            else
            {
                writeField(bOut, new BigInteger(token));
            }
        }
        return bOut.toByteArray();
    }

    static void writeField(ByteArrayOutputStream out, long fieldValue)
    {
        byte[] result = new byte[9];
        int pos = 8;
        result[pos] = (byte)((int)fieldValue & 0x7F);
        while (fieldValue >= (1L << 7))
        {
            fieldValue >>= 7;
            result[--pos] = (byte)((int)fieldValue | 0x80);
        }
        out.write(result, pos, 9 - pos);
    }

    static void writeField(ByteArrayOutputStream out, BigInteger fieldValue)
    {
        int byteCount = (fieldValue.bitLength() + 6) / 7;
        if (byteCount == 0)
        {
            out.write(0);
        }
        else
        {
            BigInteger tmpValue = fieldValue;
            byte[] tmp = new byte[byteCount];
            for (int i = byteCount - 1; i >= 0; i--)
            {
                tmp[i] = (byte)(tmpValue.intValue() | 0x80);
                tmpValue = tmpValue.shiftRight(7);
            }
            tmp[byteCount - 1] &= 0x7F;
            out.write(tmp, 0, tmp.length);
        }
    }
}
