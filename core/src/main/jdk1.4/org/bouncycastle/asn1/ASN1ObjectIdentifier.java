package org.bouncycastle.asn1;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.util.Arrays;

/**
 * Class representing the ASN.1 OBJECT IDENTIFIER type.
 */
public class ASN1ObjectIdentifier
    extends ASN1Primitive
{
    private final String identifier;

    private byte[] body;

    /**
     * return an OID from the passed in object
     * @param obj an ASN1ObjectIdentifier or an object that can be converted into one.
     * @throws IllegalArgumentException if the object cannot be converted.
     * @return an ASN1ObjectIdentifier instance, or null.
     */
    public static ASN1ObjectIdentifier getInstance(
        Object obj)
    {
        if (obj == null || obj instanceof ASN1ObjectIdentifier)
        {
            return (ASN1ObjectIdentifier)obj;
        }

        if (obj instanceof ASN1Encodable && ((ASN1Encodable)obj).toASN1Primitive() instanceof ASN1ObjectIdentifier)
        {
            return (ASN1ObjectIdentifier)((ASN1Encodable)obj).toASN1Primitive();
        }

        if (obj instanceof byte[])
        {
            byte[] enc = (byte[])obj;
            try
            {
                return (ASN1ObjectIdentifier)fromByteArray(enc);
            }
            catch (IOException e)
            {
                throw new IllegalArgumentException("failed to construct object identifier from byte[]: " + e.getMessage());
            }
        }

        throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
    }

    /**
     * return an Object Identifier from a tagged object.
     *
     * @param obj      the tagged object holding the object we want
     * @param explicit true if the object is meant to be explicitly
     *                 tagged false otherwise.
     * @throws IllegalArgumentException if the tagged object cannot
     * be converted.
     * @return an ASN1ObjectIdentifier instance, or null.
     */
    public static ASN1ObjectIdentifier getInstance(
        ASN1TaggedObject obj,
        boolean explicit)
    {
        ASN1Primitive o = obj.getObject();

        if (explicit || o instanceof ASN1ObjectIdentifier)
        {
            return getInstance(o);
        }
        else
        {
            return ASN1ObjectIdentifier.fromOctetString(ASN1OctetString.getInstance(obj.getObject()).getOctets());
        }
    }

    private static final long LONG_LIMIT = (Long.MAX_VALUE >> 7) - 0x7f;

    ASN1ObjectIdentifier(
        byte[] bytes)
    {
        StringBuffer objId = new StringBuffer();
        long value = 0;
        BigInteger bigValue = null;
        boolean first = true;

        for (int i = 0; i != bytes.length; i++)
        {
            int b = bytes[i] & 0xff;

            if (value <= LONG_LIMIT)
            {
                value += (b & 0x7f);
                if ((b & 0x80) == 0)             // end of number reached
                {
                    if (first)
                    {
                        if (value < 40)
                        {
                            objId.append('0');
                        }
                        else if (value < 80)
                        {
                            objId.append('1');
                            value -= 40;
                        }
                        else
                        {
                            objId.append('2');
                            value -= 80;
                        }
                        first = false;
                    }

                    objId.append('.');
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
                bigValue = bigValue.or(BigInteger.valueOf(b & 0x7f));
                if ((b & 0x80) == 0)
                {
                    if (first)
                    {
                        objId.append('2');
                        bigValue = bigValue.subtract(BigInteger.valueOf(80));
                        first = false;
                    }

                    objId.append('.');
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
        this.body = Arrays.clone(bytes);
    }

    /**
     * Create an OID based on the passed in String.
     *
     * @param identifier a string representation of an OID.
     */
    public ASN1ObjectIdentifier(
        String identifier)
    {
        if (identifier == null)
        {
            throw new NullPointerException("'identifier' cannot be null");
        }
        if (!isValidIdentifier(identifier))
        {
            throw new IllegalArgumentException("string " + identifier + " not an OID");
        }

        this.identifier = identifier;
    }

     /**
      * Create an OID that creates a branch under the current one.
      *
      * @param branchID node numbers for the new branch.
      * @return the OID for the new created branch.
      */
    ASN1ObjectIdentifier(ASN1ObjectIdentifier oid, String branchID)
    {
        if (!isValidBranchID(branchID, 0))
        {
            throw new IllegalArgumentException("string " + branchID + " not a valid OID branch");
        }

        this.identifier = oid.getId() + "." + branchID;
    }

    /**
     * Return the OID as a string.
     *
     * @return the string representation of the OID carried by this object.
     */
    public String getId()
    {
        return identifier;
    }

    /**
     * Return an OID that creates a branch under the current one.
     *
     * @param branchID node numbers for the new branch.
     * @return the OID for the new created branch.
     */
    public ASN1ObjectIdentifier branch(String branchID)
    {
        return new ASN1ObjectIdentifier(this, branchID);
    }

    /**
     * Return  true if this oid is an extension of the passed in branch, stem.
     *
     * @param stem the arc or branch that is a possible parent.
     * @return true if the branch is on the passed in stem, false otherwise.
     */
    public boolean on(ASN1ObjectIdentifier stem)
    {
        String id = getId(), stemId = stem.getId();
        return id.length() > stemId.length() && id.charAt(stemId.length()) == '.' && id.startsWith(stemId);
    }

    private void writeField(
        ByteArrayOutputStream out,
        long fieldValue)
    {
        byte[] result = new byte[9];
        int pos = 8;
        result[pos] = (byte)((int)fieldValue & 0x7f);
        while (fieldValue >= (1L << 7))
        {
            fieldValue >>= 7;
            result[--pos] = (byte)((int)fieldValue & 0x7f | 0x80);
        }
        out.write(result, pos, 9 - pos);
    }

    private void writeField(
        ByteArrayOutputStream out,
        BigInteger fieldValue)
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
                tmp[i] = (byte)((tmpValue.intValue() & 0x7f) | 0x80);
                tmpValue = tmpValue.shiftRight(7);
            }
            tmp[byteCount - 1] &= 0x7f;
            out.write(tmp, 0, tmp.length);
        }
    }

    private void doOutput(ByteArrayOutputStream aOut)
    {
        OIDTokenizer tok = new OIDTokenizer(identifier);
        int first = Integer.parseInt(tok.nextToken()) * 40;

        String secondToken = tok.nextToken();
        if (secondToken.length() <= 18)
        {
            writeField(aOut, first + Long.parseLong(secondToken));
        }
        else
        {
            writeField(aOut, new BigInteger(secondToken).add(BigInteger.valueOf(first)));
        }

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

    private synchronized byte[] getBody()
    {
        if (body == null)
        {
            ByteArrayOutputStream bOut = new ByteArrayOutputStream();

            doOutput(bOut);

            body = bOut.toByteArray();
        }

        return body;
    }

    boolean isConstructed()
    {
        return false;
    }

    int encodedLength()
        throws IOException
    {
        int length = getBody().length;

        return 1 + StreamUtil.calculateBodyLength(length) + length;
    }

    void encode(ASN1OutputStream out, boolean withTag) throws IOException
    {
        out.writeEncoded(withTag, BERTags.OBJECT_IDENTIFIER, getBody());
    }

    public int hashCode()
    {
        return identifier.hashCode();
    }

    boolean asn1Equals(
        ASN1Primitive o)
    {
        if (o == this)
        {
            return true;
        }

        if (!(o instanceof ASN1ObjectIdentifier))
        {
            return false;
        }

        return identifier.equals(((ASN1ObjectIdentifier)o).identifier);
    }

    public String toString()
    {
        return getId();
    }

    private static boolean isValidBranchID(
        String branchID, int start)
    {
        int digitCount = 0;

        int pos = branchID.length();
        while (--pos >= start)
        {
            char ch = branchID.charAt(pos);

            if (ch == '.')
            {
                if (0 == digitCount
                    || (digitCount > 1 && branchID.charAt(pos + 1) == '0'))
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
            || (digitCount > 1 && branchID.charAt(pos + 1) == '0'))
        {
            return false;
        }

        return true;
    }

    private static boolean isValidIdentifier(
        String identifier)
    {
        if (identifier.length() < 3 || identifier.charAt(1) != '.')
        {
            return false;
        }

        char first = identifier.charAt(0);
        if (first < '0' || first > '2')
        {
            return false;
        }

        return isValidBranchID(identifier, 2);
    }

    /**
     * Intern will return a reference to a pooled version of this object, unless it
     * is not present in which case intern will add it.
     * <p>
     * The pool is also used by the ASN.1 parsers to limit the number of duplicated OID
     * objects in circulation.
     * </p>
     * @return a reference to the identifier in the pool.
     */
    public ASN1ObjectIdentifier intern()
    {
        synchronized (pool)
        {
            OidHandle hdl = new OidHandle(getBody());
            ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier)pool.get(hdl);

            if (oid != null)
            {
                return oid;
            }
            else
            {
                pool.put(hdl, this);
                return this;
            }
        }
    }

    private static final Map pool = new HashMap();

    private static class OidHandle
    {
        private int key;
        private final byte[] enc;

        OidHandle(byte[] enc)
        {
            this.key = Arrays.hashCode(enc);
            this.enc = enc;
        }

        public int hashCode()
        {
            return key;
        }

        public boolean equals(Object o)
        {
            if (o instanceof OidHandle)
            {
                return Arrays.areEqual(enc, ((OidHandle)o).enc);
            }

            return false;
        }
    }

    static ASN1ObjectIdentifier fromOctetString(byte[] enc)
    {
        OidHandle hdl = new OidHandle(enc);

        synchronized (pool)
        {
            ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier)pool.get(hdl);
            if (oid != null)
            {
                return oid;
            }
        }

        return new ASN1ObjectIdentifier(enc);
    }
}
