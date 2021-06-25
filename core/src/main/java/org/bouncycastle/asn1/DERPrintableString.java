package org.bouncycastle.asn1;

/**
 * DER PrintableString object.
 * <p>
 * X.680 section 37.4 defines PrintableString character codes as ASCII subset of following characters:
 * </p>
 * <ul>
 * <li>Latin capital letters: 'A' .. 'Z'</li>
 * <li>Latin small letters: 'a' .. 'z'</li>
 * <li>Digits: '0'..'9'</li>
 * <li>Space</li>
 * <li>Apostrophe: '\''</li>
 * <li>Left parenthesis: '('</li>
 * <li>Right parenthesis: ')'</li>
 * <li>Plus sign: '+'</li>
 * <li>Comma: ','</li>
 * <li>Hyphen-minus: '-'</li>
 * <li>Full stop: '.'</li>
 * <li>Solidus: '/'</li>
 * <li>Colon: ':'</li>
 * <li>Equals sign: '='</li>
 * <li>Question mark: '?'</li>
 * </ul>
 * <p>
 * Explicit character set escape sequences are not allowed.
 * </p>
 */
public class DERPrintableString
    extends ASN1PrintableString
{
    /**
     * Return a printable string from the passed in object.
     *
     * @param obj a DERPrintableString or an object that can be converted into one.
     * @exception IllegalArgumentException if the object cannot be converted.
     * @return a DERPrintableString instance, or null.
     * 
     * @deprecated Use {@link ASN1PrintableString#getInstance(Object)} instead.
     */
    public static DERPrintableString getInstance(
        Object  obj)
    {
        if (obj == null || obj instanceof DERPrintableString)
        {
            return (DERPrintableString)obj;
        }
        if (obj instanceof ASN1PrintableString)
        {
            return new DERPrintableString(((ASN1PrintableString)obj).contents, false);
        }
        if (obj instanceof byte[])
        {
            try
            {
                return (DERPrintableString)fromByteArray((byte[])obj);
            }
            catch (Exception e)
            {
                throw new IllegalArgumentException("encoding error in getInstance: " + e.toString());
            }
        }

        throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
    }

    /**
     * Return a Printable String from a tagged object.
     *
     * @param obj      the tagged object holding the object we want
     * @param explicit true if the object is meant to be explicitly tagged false
     *                 otherwise.
     * @exception IllegalArgumentException if the tagged object cannot be converted.
     * @return a DERPrintableString instance, or null.
     * 
     * @deprecated Use
     *             {@link ASN1PrintableString#getInstance(ASN1TaggedObject, boolean)}
     *             instead.
     */
    public static DERPrintableString getInstance(
        ASN1TaggedObject obj,
        boolean          explicit)
    {
        ASN1Primitive o = obj.getObject();

        if (explicit || o instanceof DERPrintableString)
        {
            return getInstance(o);
        }
        else
        {
            return new DERPrintableString(ASN1OctetString.getInstance(o).getOctets(), true);
        }
    }

    /**
     * Basic constructor - this does not validate the string
     */
    public DERPrintableString(
        String   string)
    {
        this(string, false);
    }

    /**
     * Constructor with optional validation.
     *
     * @param string the base string to wrap.
     * @param validate whether or not to check the string.
     * @throws IllegalArgumentException if validate is true and the string
     * contains characters that should not be in a PrintableString.
     */
    public DERPrintableString(
        String   string,
        boolean  validate)
    {
        super(string, validate);
    }

    DERPrintableString(byte[] contents, boolean clone)
    {
        super(contents, clone);
    }
}
