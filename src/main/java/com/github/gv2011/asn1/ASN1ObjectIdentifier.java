package com.github.gv2011.asn1;

/*-
 * #%L
 * Vinz ASN.1
 * %%
 * Copyright (C) 2016 - 2017 Vinz (https://github.com/gv2011)
 * %%
 * Please note this should be read in the same way as the MIT license. (https://www.bouncycastle.org/licence.html)
 * 
 * Copyright (c) 2000-2015 The Legion of the Bouncy Castle Inc. (http://www.bouncycastle.org)
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this software 
 * and associated documentation files (the "Software"), to deal in the Software without restriction, 
 * including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, 
 * and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all copies or substantial
 * portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
 * INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
 * PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 * LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
 * OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 * #L%
 */


import static com.github.gv2011.util.bytes.ByteUtils.newBytesBuilder;


import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;

import com.github.gv2011.util.ann.Nullable;
import com.github.gv2011.util.bytes.Bytes;
import com.github.gv2011.util.bytes.BytesBuilder;

/**
 * Class representing the ASN.1 OBJECT IDENTIFIER type.
 */
public class ASN1ObjectIdentifier
    extends ASN1Primitive
{
    private final String identifier;

    private @Nullable Bytes body;

    /**
     * return an OID from the passed in object
     * @param obj an ASN1ObjectIdentifier or an object that can be converted into one.
     * @throws IllegalArgumentException if the object cannot be converted.
     * @return an ASN1ObjectIdentifier instance, or null.
     */
    public static ASN1ObjectIdentifier getInstance(
        final Object obj)
    {
        if (obj == null || obj instanceof ASN1ObjectIdentifier)
        {
            return (ASN1ObjectIdentifier)obj;
        }

        if (obj instanceof ASN1Encodable && ((ASN1Encodable)obj).toASN1Primitive() instanceof ASN1ObjectIdentifier)
        {
            return (ASN1ObjectIdentifier)((ASN1Encodable)obj).toASN1Primitive();
        }

        if (obj instanceof Bytes)
        {
            final Bytes enc = (Bytes)obj;
            return (ASN1ObjectIdentifier)fromBytes(enc);
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
        final ASN1TaggedObject obj,
        final boolean explicit)
    {
        final ASN1Primitive o = obj.getObject();

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
        final Bytes bytes)
    {
        final StringBuffer objId = new StringBuffer();
        long value = 0;
        BigInteger bigValue = null;
        boolean first = true;

        for (int i = 0; i != bytes.size(); i++)
        {
            final int b = bytes.getByte(i) & 0xff;

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

        identifier = objId.toString();
        body = bytes;
    }

    /**
     * Create an OID based on the passed in String.
     *
     * @param identifier a string representation of an OID.
     */
    public ASN1ObjectIdentifier(
        final String identifier)
    {
        if (identifier == null)
        {
            throw new IllegalArgumentException("'identifier' cannot be null");
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
    ASN1ObjectIdentifier(final ASN1ObjectIdentifier oid, final String branchID)
    {
        if (!isValidBranchID(branchID, 0))
        {
            throw new IllegalArgumentException("string " + branchID + " not a valid OID branch");
        }

        identifier = oid.getId() + "." + branchID;
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
    public ASN1ObjectIdentifier branch(final String branchID)
    {
        return new ASN1ObjectIdentifier(this, branchID);
    }

    /**
     * Return  true if this oid is an extension of the passed in branch, stem.
     *
     * @param stem the arc or branch that is a possible parent.
     * @return true if the branch is on the passed in stem, false otherwise.
     */
    public boolean on(final ASN1ObjectIdentifier stem)
    {
        final String id = getId(), stemId = stem.getId();
        return id.length() > stemId.length() && id.charAt(stemId.length()) == '.' && id.startsWith(stemId);
    }

    private void writeField(
        final BytesBuilder out,
        long fieldValue)
    {
        final byte[] result = new byte[9];
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
        final BytesBuilder out,
        final BigInteger fieldValue)
    {
        final int byteCount = (fieldValue.bitLength() + 6) / 7;
        if (byteCount == 0)
        {
            out.write(0);
        }
        else
        {
            BigInteger tmpValue = fieldValue;
            final byte[] tmp = new byte[byteCount];
            for (int i = byteCount - 1; i >= 0; i--)
            {
                tmp[i] = (byte)((tmpValue.intValue() & 0x7f) | 0x80);
                tmpValue = tmpValue.shiftRight(7);
            }
            tmp[byteCount - 1] &= 0x7f;
            out.write(tmp, 0, tmp.length);
        }
    }

    private void doOutput(final BytesBuilder aOut)
    {
        final OIDTokenizer tok = new OIDTokenizer(identifier);
        final int first = Integer.parseInt(tok.nextToken()) * 40;

        final String secondToken = tok.nextToken();
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
            final String token = tok.nextToken();
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

    private synchronized Bytes getBody()
    {
        if (body == null)
        {
            final BytesBuilder bOut = newBytesBuilder();

            doOutput(bOut);

            body = bOut.build();
        }

        return body;
    }

    @Override
    boolean isConstructed()
    {
        return false;
    }

    @Override
    int encodedLength()
    {
        final int length = getBody().size();

        return 1 + StreamUtil.calculateBodyLength(length) + length;
    }

    @Override
    void encode(
        final ASN1OutputStream out)
    {
        final Bytes enc = getBody();

        out.write(BERTags.OBJECT_IDENTIFIER);
        out.writeLength(enc.size());
        out.write(enc);
    }

    @Override
    public int hashCode()
    {
        return identifier.hashCode();
    }

    @Override
    boolean asn1Equals(
        final ASN1Primitive o)
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

    @Override
    public String toString()
    {
        return getId();
    }

    private static boolean isValidBranchID(
        final String branchID, final int start)
    {
        boolean periodAllowed = false;

        int pos = branchID.length();
        while (--pos >= start)
        {
            final char ch = branchID.charAt(pos);

            // TODO Leading zeroes?
            if ('0' <= ch && ch <= '9')
            {
                periodAllowed = true;
                continue;
            }

            if (ch == '.')
            {
                if (!periodAllowed)
                {
                    return false;
                }

                periodAllowed = false;
                continue;
            }

            return false;
        }

        return periodAllowed;
    }

    private static boolean isValidIdentifier(
        final String identifier)
    {
        if (identifier.length() < 3 || identifier.charAt(1) != '.')
        {
            return false;
        }

        final char first = identifier.charAt(0);
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
    @SuppressWarnings("unchecked")
    public ASN1ObjectIdentifier intern()
    {
        synchronized (pool)
        {
            final OidHandle hdl = new OidHandle(getBody());
            final ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier)pool.get(hdl);

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

    @SuppressWarnings("rawtypes")
    private static final Map pool = new HashMap();

    private static class OidHandle
    {
        private final int key;
        private final Bytes enc;

        OidHandle(final Bytes enc)
        {
            key = enc.hashCode();
            this.enc = enc;
        }

        @Override
        public int hashCode()
        {
            return key;
        }

        @Override
        public boolean equals(final Object o)
        {
            if (o instanceof OidHandle)
            {
                return enc.equals(((OidHandle)o).enc);
            }

            return false;
        }
    }

    static ASN1ObjectIdentifier fromOctetString(final Bytes enc)
    {
        final OidHandle hdl = new OidHandle(enc);

        synchronized (pool)
        {
            final ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier)pool.get(hdl);
            if (oid != null)
            {
                return oid;
            }
        }

        return new ASN1ObjectIdentifier(enc);
    }
}
