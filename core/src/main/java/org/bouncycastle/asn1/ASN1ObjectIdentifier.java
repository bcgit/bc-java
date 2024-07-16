package org.bouncycastle.asn1;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import org.bouncycastle.util.Arrays;

/**
 * Class representing the ASN.1 OBJECT IDENTIFIER type.
 */
public class ASN1ObjectIdentifier
    extends ASN1Primitive
{
    static final ASN1UniversalType TYPE = new ASN1UniversalType(ASN1ObjectIdentifier.class, BERTags.OBJECT_IDENTIFIER)
    {
        ASN1Primitive fromImplicitPrimitive(DEROctetString octetString)
        {
            return createPrimitive(octetString.getOctets(), false);
        }
    };

    /**
     * Implementation limit on the length of the contents octets for an Object Identifier.
     * <p/>
     * We adopt the same value used by OpenJDK. In theory there is no limit on the length of the contents, or
     * the number of subidentifiers, or the length of individual subidentifiers. In practice, supporting
     * arbitrary lengths can lead to issues, e.g. denial-of-service attacks when attempting to convert a
     * parsed value to its (decimal) string form.
     */
    private static final int MAX_CONTENTS_LENGTH = 4096;
    private static final int MAX_IDENTIFIER_LENGTH = MAX_CONTENTS_LENGTH * 4 + 1;

    public static ASN1ObjectIdentifier fromContents(byte[] contents)
    {
        if (contents == null)
        {
            throw new NullPointerException("'contents' cannot be null");
        }

        return createPrimitive(contents, true);
    }

    /**
     * Return an OID from the passed in object
     *
     * @param obj an ASN1ObjectIdentifier or an object that can be converted into one.
     * @return an ASN1ObjectIdentifier instance, or null.
     * @throws IllegalArgumentException if the object cannot be converted.
     */
    public static ASN1ObjectIdentifier getInstance(Object obj)
    {
        if (obj == null || obj instanceof ASN1ObjectIdentifier)
        {
            return (ASN1ObjectIdentifier)obj;
        }
        else if (obj instanceof ASN1Encodable)
        {
            ASN1Primitive primitive = ((ASN1Encodable)obj).toASN1Primitive();
            if (primitive instanceof ASN1ObjectIdentifier)
            {
                return (ASN1ObjectIdentifier)primitive;
            }
        }
        else if (obj instanceof byte[])
        {
            try
            {
                return (ASN1ObjectIdentifier)TYPE.fromByteArray((byte[])obj);
            }
            catch (IOException e)
            {
                throw new IllegalArgumentException("failed to construct object identifier from byte[]: " + e.getMessage());
            }
        }

        throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
    }

    /**
     * Return an OBJECT IDENTIFIER from a tagged object.
     *
     * @param taggedObject      the tagged object holding the object we want
     * @param explicit true if the object is meant to be explicitly
     *                 tagged false otherwise.
     * @return an ASN1ObjectIdentifier instance, or null.
     * @throws IllegalArgumentException if the tagged object cannot
     * be converted.
     */
    public static ASN1ObjectIdentifier getInstance(ASN1TaggedObject taggedObject, boolean explicit)
    {
        /*
         * TODO[asn1] This block here is for backward compatibility, but should eventually be removed.
         * 
         * - see https://github.com/bcgit/bc-java/issues/1015
         */
        if (!explicit && !taggedObject.isParsed() && taggedObject.hasContextTag())
        {
            ASN1Primitive base = taggedObject.getBaseObject().toASN1Primitive();
            if (!(base instanceof ASN1ObjectIdentifier))
            {
                return fromContents(ASN1OctetString.getInstance(base).getOctets());
            }
        }

        return (ASN1ObjectIdentifier)TYPE.getContextInstance(taggedObject, explicit);
    }

    public static ASN1ObjectIdentifier tryFromID(String identifier)
    {
        if (identifier == null)
        {
            throw new NullPointerException("'identifier' cannot be null");
        }
        if (identifier.length() <= MAX_IDENTIFIER_LENGTH && isValidIdentifier(identifier))
        {
            byte[] contents = parseIdentifier(identifier);
            if (contents.length <= MAX_CONTENTS_LENGTH)
            {
                return new ASN1ObjectIdentifier(contents, identifier);
            }
        }

        return null;
    }

    private static final long LONG_LIMIT = (Long.MAX_VALUE >> 7) - 0x7F;

    private static final ConcurrentMap<OidHandle, ASN1ObjectIdentifier> pool =
        new ConcurrentHashMap<OidHandle, ASN1ObjectIdentifier>();

    private final byte[] contents;
    private String identifier;

    /**
     * Create an OID based on the passed in String.
     *
     * @param identifier a string representation of an OID.
     */
    public ASN1ObjectIdentifier(String identifier)
    {
        checkIdentifier(identifier);

        byte[] contents = parseIdentifier(identifier);
        checkContentsLength(contents.length);

        this.contents = contents;
        this.identifier = identifier;
    }

    private ASN1ObjectIdentifier(byte[] contents, String identifier)
    {
        this.contents = contents;
        this.identifier = identifier;
    }

    /**
     * Return an OID that creates a branch under the current one.
     *
     * @param branchID node numbers for the new branch.
     * @return the OID for the new created branch.
     */
    public ASN1ObjectIdentifier branch(String branchID)
    {
        ASN1RelativeOID.checkIdentifier(branchID);

        byte[] contents;
        if (branchID.length() <= 2)
        {
            checkContentsLength(this.contents.length + 1);
            int subID = branchID.charAt(0) - '0';
            if (branchID.length() == 2)
            {
                subID *= 10;
                subID += branchID.charAt(1) - '0';
            }

            contents = Arrays.append(this.contents, (byte)subID);
        }
        else
        {
            byte[] branchContents = ASN1RelativeOID.parseIdentifier(branchID);
            checkContentsLength(this.contents.length + branchContents.length);

            contents = Arrays.concatenate(this.contents, branchContents);
        }

        String rootID = getId();
        String identifier = rootID + "." + branchID;

        return new ASN1ObjectIdentifier(contents, identifier);
    }

    /**
     * Return the OID as a string.
     *
     * @return the string representation of the OID carried by this object.
     */
    public synchronized String getId()
    {
        if (identifier == null)
        {
            identifier = parseContents(contents);
        }

        return identifier;
    }

    /**
     * Return true if this oid is an extension of the passed in branch - stem.
     *
     * @param stem the arc or branch that is a possible parent.
     * @return true if the branch is on the passed in stem, false otherwise.
     */
    public boolean on(ASN1ObjectIdentifier stem)
    {
        byte[] contents = this.contents, stemContents = stem.contents;
        int stemLength = stemContents.length;

        return contents.length > stemLength
            && Arrays.areEqual(contents, 0, stemLength, stemContents, 0, stemLength);
    }

    boolean encodeConstructed()
    {
        return false;
    }

    int encodedLength(boolean withTag)
    {
        return ASN1OutputStream.getLengthOfEncodingDL(withTag, contents.length);
    }

    void encode(ASN1OutputStream out, boolean withTag) throws IOException
    {
        out.writeEncodingDL(withTag, BERTags.OBJECT_IDENTIFIER, contents);
    }

    public int hashCode()
    {
        return Arrays.hashCode(contents);
    }

    boolean asn1Equals(ASN1Primitive other)
    {
        if (this == other)
        {
            return true;
        }
        if (!(other instanceof ASN1ObjectIdentifier))
        {
            return false;
        }

        ASN1ObjectIdentifier that = (ASN1ObjectIdentifier)other;

        return Arrays.areEqual(this.contents, that.contents);
    }

    public String toString()
    {
        return getId();
    }

    static void checkContentsLength(int contentsLength)
    {
        if (contentsLength > MAX_CONTENTS_LENGTH)
        {
            throw new IllegalArgumentException("exceeded OID contents length limit");
        }
    }

    static void checkIdentifier(String identifier)
    {
        if (identifier == null)
        {
            throw new NullPointerException("'identifier' cannot be null");
        }
        if (identifier.length() > MAX_IDENTIFIER_LENGTH)
        {
            throw new IllegalArgumentException("exceeded OID contents length limit");
        }
        if (!isValidIdentifier(identifier))
        {
            throw new IllegalArgumentException("string " + identifier + " not a valid OID");
        }
    }

    static ASN1ObjectIdentifier createPrimitive(byte[] contents, boolean clone)
    {
        checkContentsLength(contents.length);
        
        final OidHandle hdl = new OidHandle(contents);
        ASN1ObjectIdentifier oid = pool.get(hdl);
        if (oid != null)
        {
            return oid;
        }

        if (!ASN1RelativeOID.isValidContents(contents))
        {
            throw new IllegalArgumentException("invalid OID contents");
        }

        return new ASN1ObjectIdentifier(clone ? Arrays.clone(contents) : contents, null);
    }

    private static boolean isValidIdentifier(String identifier)
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

        if (!ASN1RelativeOID.isValidIdentifier(identifier, 2))
        {
            return false;
        }

        if (first == '2')
        {
            return true;
        }

        if (identifier.length() == 3 || identifier.charAt(3) == '.')
        {
            return true;
        }

        if (identifier.length() == 4 || identifier.charAt(4) == '.')
        {
            return identifier.charAt(2) < '4';
        }

        return false;
    }

    private static String parseContents(byte[] contents)
    {
        StringBuilder objId = new StringBuilder();
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
                bigValue = bigValue.or(BigInteger.valueOf(b & 0x7F));
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

        return objId.toString();
    }

    private static byte[] parseIdentifier(String identifier)
    {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        OIDTokenizer tok = new OIDTokenizer(identifier);
        int first = Integer.parseInt(tok.nextToken()) * 40;

        String secondToken = tok.nextToken();
        if (secondToken.length() <= 18)
        {
            ASN1RelativeOID.writeField(bOut, first + Long.parseLong(secondToken));
        }
        else
        {
            ASN1RelativeOID.writeField(bOut, new BigInteger(secondToken).add(BigInteger.valueOf(first)));
        }

        while (tok.hasMoreTokens())
        {
            String token = tok.nextToken();
            if (token.length() <= 18)
            {
                ASN1RelativeOID.writeField(bOut, Long.parseLong(token));
            }
            else
            {
                ASN1RelativeOID.writeField(bOut, new BigInteger(token));
            }
        }

        return bOut.toByteArray();
    }

    /**
     * Intern will return a reference to a pooled version of this object, unless it
     * is not present in which case intern will add it.
     * <p>
     * The pool is also used by the ASN.1 parsers to limit the number of duplicated OID
     * objects in circulation.
     * </p>
     *
     * @return a reference to the identifier in the pool.
     */
    public ASN1ObjectIdentifier intern()
    {
        final OidHandle hdl = new OidHandle(contents);
        ASN1ObjectIdentifier oid = pool.get(hdl);
        if (oid == null)
        {
            synchronized (pool)
            {
                if (!pool.containsKey(hdl))
                {
                    pool.put(hdl, this);
                    return this;
                }
                else
                {
                    return pool.get(hdl);
                }
            }
        }
        return oid;
    }

    static class OidHandle
    {
        private final int key;
        private final byte[] contents;

        OidHandle(byte[] contents)
        {
            this.key = Arrays.hashCode(contents);
            this.contents = contents;
        }

        public int hashCode()
        {
            return key;
        }

        public boolean equals(Object o)
        {
            if (o instanceof OidHandle)
            {
                return Arrays.areEqual(contents, ((OidHandle)o).contents);
            }

            return false;
        }
    }
}
