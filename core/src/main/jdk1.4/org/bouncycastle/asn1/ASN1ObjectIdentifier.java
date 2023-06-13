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
    static final ASN1UniversalType TYPE = new ASN1UniversalType(ASN1ObjectIdentifier.class, BERTags.OBJECT_IDENTIFIER)
    {
        ASN1Primitive fromImplicitPrimitive(DEROctetString octetString)
        {
            return createPrimitive(octetString.getOctets(), false);
        }
    };

    public static ASN1ObjectIdentifier fromContents(byte[] contents)
    {
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
        if (!explicit && !taggedObject.isParsed() && BERTags.CONTEXT_SPECIFIC == taggedObject.getTagClass())
        {
            ASN1Primitive base = taggedObject.getBaseObject().toASN1Primitive();
            if (!(base instanceof ASN1ObjectIdentifier))
            {
                return fromContents(ASN1OctetString.getInstance(base).getOctets());
            }
        }

        return (ASN1ObjectIdentifier)TYPE.getContextInstance(taggedObject, explicit);
    }

    private static final long LONG_LIMIT = (Long.MAX_VALUE >> 7) - 0x7F;

    private static final Map pool = new HashMap();

    private final String identifier;
    private byte[] contents;

    ASN1ObjectIdentifier(byte[] contents, boolean clone)
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

        this.identifier = objId.toString();
        this.contents = clone ? Arrays.clone(contents) : contents;
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
        if (!ASN1RelativeOID.isValidIdentifier(branchID, 0))
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
     * Return true if this oid is an extension of the passed in branch - stem.
     *
     * @param stem the arc or branch that is a possible parent.
     * @return true if the branch is on the passed in stem, false otherwise.
     */
    public boolean on(ASN1ObjectIdentifier stem)
    {
        String id = getId(), stemId = stem.getId();
        return id.length() > stemId.length() && id.charAt(stemId.length()) == '.' && id.startsWith(stemId);
    }

    private void doOutput(ByteArrayOutputStream aOut)
    {
        OIDTokenizer tok = new OIDTokenizer(identifier);
        int first = Integer.parseInt(tok.nextToken()) * 40;

        String secondToken = tok.nextToken();
        if (secondToken.length() <= 18)
        {
            ASN1RelativeOID.writeField(aOut, first + Long.parseLong(secondToken));
        }
        else
        {
            ASN1RelativeOID.writeField(aOut, new BigInteger(secondToken).add(BigInteger.valueOf(first)));
        }

        while (tok.hasMoreTokens())
        {
            String token = tok.nextToken();
            if (token.length() <= 18)
            {
                ASN1RelativeOID.writeField(aOut, Long.parseLong(token));
            }
            else
            {
                ASN1RelativeOID.writeField(aOut, new BigInteger(token));
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

    boolean encodeConstructed()
    {
        return false;
    }

    int encodedLength(boolean withTag)
    {
        return ASN1OutputStream.getLengthOfEncodingDL(withTag, getContents().length);
    }

    void encode(ASN1OutputStream out, boolean withTag) throws IOException
    {
        out.writeEncodingDL(withTag, BERTags.OBJECT_IDENTIFIER, getContents());
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

        return ASN1RelativeOID.isValidIdentifier(identifier, 2);
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
        final OidHandle hdl = new OidHandle(getContents());
        synchronized (pool)
        {
            ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier)pool.get(hdl);
            if (oid == null)
            {
                oid = (ASN1ObjectIdentifier)pool.put(hdl, this);
                if (oid == null)
                {
                    oid = this;
                }
            }
            return oid;
        }
    }

    private static class OidHandle
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

    static ASN1ObjectIdentifier createPrimitive(byte[] contents, boolean clone)
    {
        final OidHandle hdl = new OidHandle(contents);
        synchronized (pool)
        {
            ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier)pool.get(hdl);
            if (oid == null)
            {
                return new ASN1ObjectIdentifier(contents, clone);
            }
            return oid;
        }
    }
}
