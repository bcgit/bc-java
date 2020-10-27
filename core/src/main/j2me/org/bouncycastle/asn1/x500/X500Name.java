package org.bouncycastle.asn1.x500;

import java.util.Enumeration;

import org.bouncycastle.asn1.ASN1Choice;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x500.style.BCStyle;

/**
 * The X.500 Name object.
 * <pre>
 *     Name ::= CHOICE {
 *                       RDNSequence }
 *
 *     RDNSequence ::= SEQUENCE OF RelativeDistinguishedName
 *
 *     RelativeDistinguishedName ::= SET SIZE (1..MAX) OF AttributeTypeAndValue
 *
 *     AttributeTypeAndValue ::= SEQUENCE {
 *                                   type  OBJECT IDENTIFIER,
 *                                   value ANY }
 * </pre>
 */
public class X500Name
    extends ASN1Object
    implements ASN1Choice
{
    private static X500NameStyle    defaultStyle = BCStyle.INSTANCE;

    private boolean                 isHashCodeCalculated;
    private int                     hashCodeValue;

    private X500NameStyle style;
    private RDN[] rdns;
    private DERSequence rdnSeq;

    /**
     * @deprecated use the getInstance() method that takes a style.
     */
    public X500Name(X500NameStyle style, X500Name name)
    {
        this.style = style;
        this.rdns = name.rdns;
        this.rdnSeq = name.rdnSeq;
    }

    /**
     * Return a X500Name based on the passed in tagged object.
     * 
     * @param obj tag object holding name.
     * @param explicit true if explicitly tagged false otherwise.
     * @return the X500Name
     */
    public static X500Name getInstance(
        ASN1TaggedObject obj,
        boolean          explicit)
    {
        // must be true as choice item
        return getInstance(ASN1Sequence.getInstance(obj, true));
    }

    public static X500Name getInstance(
        Object  obj)
    {
        if (obj instanceof X500Name)
        {
            return (X500Name)obj;
        }
        else if (obj != null)
        {
            return new X500Name(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    public static X500Name getInstance(
        X500NameStyle style,
        Object        obj)
    {
        if (obj instanceof X500Name)
        {
            return new X500Name(style, (X500Name)obj);
        }
        else if (obj != null)
        {
            return new X500Name(style, ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    /**
     * Constructor from ASN1Sequence
     *
     * the principal will be a list of constructed sets, each containing an (OID, String) pair.
     */
    private X500Name(
        ASN1Sequence  seq)
    {
        this(defaultStyle, seq);
    }

    private X500Name(
        X500NameStyle style,
        ASN1Sequence  seq)
    {
        this.style = style;
        this.rdns = new RDN[seq.size()];

        boolean inPlace = true;

        int index = 0;
        for (Enumeration e = seq.getObjects(); e.hasMoreElements();)
        {
            Object element = e.nextElement();
            RDN rdn = RDN.getInstance(element);
            inPlace &= (rdn == element);
            rdns[index++] = rdn;
        }

        if (inPlace)
        {
            this.rdnSeq = DERSequence.convert(seq);
        }
        else
        {
            this.rdnSeq = new DERSequence(this.rdns);
        }
    }

    public X500Name(
        RDN[] rDNs)
    {
        this(defaultStyle, rDNs);
    }

    public X500Name(
        X500NameStyle style,
        RDN[]         rDNs)
    {
        this.style = style;
        
        this.rdns = new RDN[rDNs.length];
        System.arraycopy(rDNs, 0, this.rdns, 0, this.rdns.length);
        this.rdnSeq = new DERSequence(this.rdns);
    }

    public X500Name(
        String dirName)
    {
        this(defaultStyle, dirName);
    }

    public X500Name(
        X500NameStyle style,
        String        dirName)
    {
        this(style.fromString(dirName));

        this.style = style;
    }

    /**
     * return an array of RDNs in structure order.
     *
     * @return an array of RDN objects.
     */
    public RDN[] getRDNs()
    {
        RDN[] rv = new RDN[this.rdns.length];
        System.arraycopy(this.rdns, 0, rv, 0, this.rdns.length);
        return rv;
    }

    /**
     * return an array of OIDs contained in the attribute type of each RDN in structure order.
     *
     * @return an array, possibly zero length, of ASN1ObjectIdentifiers objects.
     */
    public ASN1ObjectIdentifier[] getAttributeTypes()
    {
        int count = rdns.length, totalSize = 0;
        for (int i = 0; i < count; ++i)
        {
            RDN rdn = rdns[i];
            totalSize += rdn.size();
        }

        ASN1ObjectIdentifier[] oids = new ASN1ObjectIdentifier[totalSize];
        int oidsOff = 0;
        for (int i = 0; i < count; ++i)
        {
            RDN rdn = rdns[i];
            oidsOff += rdn.collectAttributeTypes(oids, oidsOff);
        }
        return oids;
    }

    /**
     * return an array of RDNs containing the attribute type given by OID in structure order.
     *
     * @param attributeType the type OID we are looking for.
     * @return an array, possibly zero length, of RDN objects.
     */
    public RDN[] getRDNs(ASN1ObjectIdentifier attributeType)
    {
        RDN[] res = new RDN[rdns.length];
        int count = 0;

        for (int i = 0; i != rdns.length; i++)
        {
            RDN rdn = rdns[i];
            if (rdn.containsAttributeType(attributeType))
            {
                res[count++] = rdn;
            }
        }

        if (count < res.length)
        {
            RDN[] tmp = new RDN[count];
            System.arraycopy(res, 0, tmp, 0, tmp.length);
            res = tmp;
        }

        return res;
    }

    public ASN1Primitive toASN1Primitive()
    {
        return rdnSeq;
    }

    public int hashCode()
    {
        if (isHashCodeCalculated)
        {
            return hashCodeValue;
        }

        hashCodeValue = style.calculateHashCode(this);

        isHashCodeCalculated = true;

        return hashCodeValue;
    }

    /**
     * test for equality - note: case is ignored.
     */
    public boolean equals(Object obj)
    {
        if (obj == this)
        {
            return true;
        }

        if (!(obj instanceof X500Name || obj instanceof ASN1Sequence))
        {
            return false;
        }
        
        ASN1Primitive derO = ((ASN1Encodable)obj).toASN1Primitive();

        if (this.toASN1Primitive().equals(derO))
        {
            return true;
        }

        try
        {
            return style.areEqual(this, new X500Name(ASN1Sequence.getInstance(((ASN1Encodable)obj).toASN1Primitive())));
        }
        catch (Exception e)
        {
            return false;
        }
    }
    
    public String toString()
    {
        return style.toString(this);
    }

    /**
     * Set the default style for X500Name construction.
     *
     * @param style  an X500NameStyle
     */
    public static void setDefaultStyle(X500NameStyle style)
    {
        if (style == null)
        {
            throw new NullPointerException("cannot set style to null");
        }

        defaultStyle = style;
    }

    /**
     * Return the current default style.
     *
     * @return default style for X500Name construction.
     */
    public static X500NameStyle getDefaultStyle()
    {
        return defaultStyle;
    }
}
