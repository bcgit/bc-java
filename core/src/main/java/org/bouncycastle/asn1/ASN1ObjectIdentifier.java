package org.bouncycastle.asn1;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Exceptions;

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
                throw Exceptions.illegalArgumentException("failed to construct object identifier from byte[]", e);
            }
        }

        throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
    }

    /**
     * Return an OBJECT IDENTIFIER from a tagged object.
     *
     * @param taggedObject      the tagged object holding the object we want
     * @param declaredExplicit true if the object is meant to be explicitly
     *                 tagged false otherwise.
     * @return an ASN1ObjectIdentifier instance, or null.
     * @throws IllegalArgumentException if the tagged object cannot
     * be converted.
     */
    public static ASN1ObjectIdentifier getInstance(ASN1TaggedObject taggedObject, boolean declaredExplicit)
    {
        /*
         * TODO[asn1] This block here is for backward compatibility, but should eventually be removed.
         * 
         * - see https://github.com/bcgit/bc-java/issues/1015
         */
        if (!declaredExplicit && !taggedObject.isParsed() && taggedObject.hasContextTag())
        {
            ASN1Primitive base = taggedObject.getBaseObject().toASN1Primitive();
            if (!(base instanceof ASN1ObjectIdentifier))
            {
                return fromContents(ASN1OctetString.getInstance(base).getOctets());
            }
        }

        return (ASN1ObjectIdentifier)TYPE.getContextTagged(taggedObject, declaredExplicit);
    }

    public static ASN1ObjectIdentifier getTagged(ASN1TaggedObject taggedObject, boolean declaredExplicit)
    {
        return (ASN1ObjectIdentifier)TYPE.getTagged(taggedObject, declaredExplicit);
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

    /**
     * The identifier read from empty contents under the "org.bouncycastle.asn1.allow_wrong_oid_enc"
     * override. Empty contents are not valid, and no valid contents could stand for them, so they are
     * taken as they are: this is the one instance with empty contents, and it lives outside the pool.
     */
    private static final ASN1ObjectIdentifier EMPTY = new ASN1ObjectIdentifier(new byte[0], null, "");

    /*
     * contents is the value, which equals, hashCode, getId, on and branch work on: valid contents octets,
     * or, for EMPTY only, empty contents. When the "org.bouncycastle.asn1.allow_wrong_oid_enc" override
     * admitted an invalid encoding, contents holds what it was read as (see
     * ASN1RelativeOID.correctedContents), malformedContents holds the octets as received, and the encoding
     * writes those, so that the input round-trips; otherwise malformedContents is null and the encoding
     * writes contents. The pool only ever holds instances without malformedContents, and never EMPTY.
     */
    private final byte[] contents;
    private final byte[] malformedContents;
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
        this.malformedContents = null;
        this.identifier = identifier;
    }

    private ASN1ObjectIdentifier(byte[] contents, String identifier)
    {
        this(contents, null, identifier);
    }

    private ASN1ObjectIdentifier(byte[] contents, byte[] malformedContents, String identifier)
    {
        this.contents = contents;
        this.malformedContents = malformedContents;
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

        if (this.contents.length == 0)
        {
            throw new IllegalStateException("empty identifier has no branches");
        }

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

        // The empty identifier (read only under allow_wrong_oid_enc) is on nothing's path, and nothing is on its.
        return stemLength > 0 && contents.length > stemLength
            && Arrays.areEqual(contents, 0, stemLength, stemContents, 0, stemLength);
    }

    boolean encodeConstructed()
    {
        return false;
    }

    int encodedLength(boolean withTag)
    {
        byte[] encodingContents = malformedContents != null ? malformedContents : contents;

        return ASN1OutputStream.getLengthOfEncodingDL(withTag, encodingContents.length);
    }

    void encode(ASN1OutputStream out, boolean withTag) throws IOException
    {
        byte[] encodingContents = malformedContents != null ? malformedContents : contents;

        out.writeEncodingDL(withTag, BERTags.OBJECT_IDENTIFIER, encodingContents);
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

    private static int checkContentsLength(int contentsLength)
    {
        if (contentsLength > MAX_CONTENTS_LENGTH)
        {
            throw new IllegalArgumentException("exceeded OID contents length limit");
        }
        return contentsLength;
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

    static ASN1ObjectIdentifier createPrimitive(DefiniteLengthInputStream defIn, byte[] tmp) throws IOException
    {
        int contentsLength = checkContentsLength(defIn.getRemaining());

        boolean useTmp = contentsLength <= tmp.length;
        if (useTmp)
        {
            defIn.readAllIntoByteArray(tmp);
        }
        else
        {
            tmp = defIn.toByteArray();
        }

        return createPrimitive(tmp, contentsLength, useTmp);
    }

    private static ASN1ObjectIdentifier createPrimitive(byte[] contents, boolean clone)
    {
        return createPrimitive(contents, checkContentsLength(contents.length), clone);
    }

    private static ASN1ObjectIdentifier createPrimitive(byte[] contents, int contentsLength, boolean clone)
    {
//        assert clone || contents.length == contentsLength;

        final OidHandle hdl = new OidHandle(contents, contentsLength);
        ASN1ObjectIdentifier oid = pool.get(hdl);
        if (oid != null)
        {
            return oid;
        }

        if (!ASN1RelativeOID.isValidContents(contents, contentsLength))
        {
            if (!ASN1RelativeOID.allowWrongEncoding())
            {
                throw new IllegalArgumentException("invalid OID contents");
            }
            if (contentsLength == 0)
            {
                return EMPTY;
            }

            byte[] corrected = ASN1RelativeOID.correctedContents(contents, contentsLength);
            byte[] malformed = clone ? Arrays.copyOfRange(contents, 0, contentsLength) : contents;

            return new ASN1ObjectIdentifier(corrected, malformed, null);
        }

        byte[] newContents = clone ? Arrays.copyOfRange(contents, 0, contentsLength) : contents;

        return new ASN1ObjectIdentifier(newContents, null);
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
        int contentsLimit = identifier.length() / 2;
        ByteArrayOutputStream buf = new ByteArrayOutputStream(contentsLimit);

        int extra = (int)(identifier.charAt(0) - '0') * 40;

        int i = 2, j = 2;
        while (++j < identifier.length())
        {
            if (identifier.charAt(j) == '.')
            {
                writeField(buf, identifier, i, j, extra);
                extra = 0;
                i = j + 1;
                j = i;
            }
        }
        writeField(buf, identifier, i, j, extra);

        return buf.toByteArray();
    }

    static void writeField(ByteArrayOutputStream buf, String identifier, int from, int to, int extra)
    {
        String token = identifier.substring(from, to);
        if (token.length() <= 18)
        {
            long fieldValue = Long.parseLong(token) + extra;
            ASN1RelativeOID.writeField(buf, fieldValue);
        }
        else
        {
            BigInteger fieldValue = new BigInteger(token).add(BigInteger.valueOf(extra));
            ASN1RelativeOID.writeField(buf, fieldValue);
        }
    }

    /**
     * Intern will return a reference to a pooled version of this object, unless it
     * is not present in which case intern will add it.
     * <p>
     * The pool is also used by the ASN.1 parsers to limit the number of duplicated OID
     * objects in circulation.
     * </p>
     * <p>
     * The pool holds valid encodings only. An identifier parsed from an invalid encoding under the
     * "org.bouncycastle.asn1.allow_wrong_oid_enc" override is pooled, and returned, as the identifier it
     * was read as: an equal identifier with the valid encoding, and so never this one. The result does not
     * carry the encoding as received, so an identifier that is to be re-encoded as it came should not be
     * interned. The identifier read from empty contents is a single instance already, and is returned as
     * it is.
     * </p>
     *
     * @return a reference to the identifier in the pool.
     */
    public ASN1ObjectIdentifier intern()
    {
        if (contents.length == 0)
        {
            return EMPTY;
        }

        ASN1ObjectIdentifier valid = malformedContents == null ? this
            : new ASN1ObjectIdentifier(contents, identifier);

        final OidHandle hdl = new OidHandle(contents, contents.length);
        ASN1ObjectIdentifier oid = pool.get(hdl);
        if (oid == null)
        {
            synchronized (pool)
            {
                if (!pool.containsKey(hdl))
                {
                    pool.put(hdl, valid);
                    return valid;
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
        private final byte[] contents;
        private final int contentsLength;
        private final int key;

        OidHandle(byte[] contents, int contentsLength)
        {
            this.contents = contents;
            this.contentsLength = contentsLength;
            this.key = Arrays.hashCode(contents, 0, contentsLength);
        }

        public int hashCode()
        {
            return key;
        }

        public boolean equals(Object o)
        {
            if (o instanceof OidHandle)
            {
                OidHandle that = (OidHandle)o;
                return Arrays.areEqual(this.contents, 0, this.contentsLength, that.contents, 0, that.contentsLength);    
            }

            return false;
        }
    }
}
