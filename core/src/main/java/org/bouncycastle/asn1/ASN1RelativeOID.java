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

    private static final long LONG_LIMIT = (Long.MAX_VALUE >> 7) - 0x7F;

    private final String identifier;
    private byte[] contents;

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

        this.identifier = identifier;
    }

    ASN1RelativeOID(ASN1RelativeOID oid, String branchID)
    {
        if (!isValidIdentifier(branchID, 0))
        {
            throw new IllegalArgumentException("string " + branchID + " not a valid OID branch");
        }

        this.identifier = oid.getId() + "." + branchID;
    }

    private ASN1RelativeOID(byte[] contents, boolean clone)
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

        this.identifier = objId.toString();
        this.contents = clone ? Arrays.clone(contents) : contents;
    }

    public ASN1RelativeOID branch(String branchID)
    {
        return new ASN1RelativeOID(this, branchID);
    }

    public String getId()
    {
        return identifier;
    }

    public int hashCode()
    {
        return identifier.hashCode();
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

        return this.identifier.equals(that.identifier);
    }

    int encodedLength(boolean withTag)
    {
        return ASN1OutputStream.getLengthOfEncodingDL(withTag, getContents().length);
    }

    void encode(ASN1OutputStream out, boolean withTag) throws IOException
    {
        out.writeEncodingDL(withTag, BERTags.RELATIVE_OID, getContents());
    }

    boolean encodeConstructed()
    {
        return false;
    }

    private void doOutput(ByteArrayOutputStream aOut)
    {
        OIDTokenizer tok = new OIDTokenizer(identifier);
        while (tok.hasMoreTokens())
        {
            String token = tok.nextToken();
            if (token.length() <= 18)
            {
                writeField(aOut, Long.parseLong(token));
            }
            else
            {
                writeField(aOut, new BigInteger(token));
            }
        }
    }

    private synchronized byte[] getContents()
    {
        if (contents == null)
        {
            ByteArrayOutputStream bOut = new ByteArrayOutputStream();

            doOutput(bOut);

            contents = bOut.toByteArray();
        }

        return contents;
    }

    static ASN1RelativeOID createPrimitive(byte[] contents, boolean clone)
    {
        return new ASN1RelativeOID(contents, clone);
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
                if (0 == digitCount
                    || (digitCount > 1 && identifier.charAt(pos + 1) == '0'))
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

        if (0 == digitCount
            || (digitCount > 1 && identifier.charAt(pos + 1) == '0'))
        {
            return false;
        }

        return true;
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
