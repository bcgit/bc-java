package com.github.gv2011.bcasn.asn1.x500;

import com.github.gv2011.bcasn.asn1.ASN1Choice;
import com.github.gv2011.bcasn.asn1.ASN1Encodable;
import com.github.gv2011.bcasn.asn1.ASN1Object;
import com.github.gv2011.bcasn.asn1.ASN1Primitive;
import com.github.gv2011.bcasn.asn1.ASN1String;
import com.github.gv2011.bcasn.asn1.ASN1TaggedObject;
import com.github.gv2011.bcasn.asn1.DERBMPString;
import com.github.gv2011.bcasn.asn1.DERPrintableString;
import com.github.gv2011.bcasn.asn1.DERT61String;
import com.github.gv2011.bcasn.asn1.DERUTF8String;
import com.github.gv2011.bcasn.asn1.DERUniversalString;

/**
 * The DirectoryString CHOICE object.
 */
public class DirectoryString
    extends ASN1Object
    implements ASN1Choice, ASN1String
{
    private ASN1String string;

    public static DirectoryString getInstance(Object o)
    {
        if (o == null || o instanceof DirectoryString)
        {
            return (DirectoryString)o;
        }

        if (o instanceof DERT61String)
        {
            return new DirectoryString((DERT61String)o);
        }

        if (o instanceof DERPrintableString)
        {
            return new DirectoryString((DERPrintableString)o);
        }

        if (o instanceof DERUniversalString)
        {
            return new DirectoryString((DERUniversalString)o);
        }

        if (o instanceof DERUTF8String)
        {
            return new DirectoryString((DERUTF8String)o);
        }

        if (o instanceof DERBMPString)
        {
            return new DirectoryString((DERBMPString)o);
        }

        throw new IllegalArgumentException("illegal object in getInstance: " + o.getClass().getName());
    }

    public static DirectoryString getInstance(ASN1TaggedObject o, boolean explicit)
    {
        if (!explicit)
        {
            throw new IllegalArgumentException("choice item must be explicitly tagged");
        }

        return getInstance(o.getObject());
    }

    private DirectoryString(
        DERT61String string)
    {
        this.string = string;
    }

    private DirectoryString(
        DERPrintableString string)
    {
        this.string = string;
    }

    private DirectoryString(
        DERUniversalString string)
    {
        this.string = string;
    }

    private DirectoryString(
        DERUTF8String string)
    {
        this.string = string;
    }

    private DirectoryString(
        DERBMPString string)
    {
        this.string = string;
    }

    public DirectoryString(String string)
    {
        this.string = new DERUTF8String(string);
    }

    public String getString()
    {
        return string.getString();
    }

    public String toString()
    {
        return string.getString();
    }

    /**
     * <pre>
     *  DirectoryString ::= CHOICE {
     *    teletexString               TeletexString (SIZE (1..MAX)),
     *    printableString             PrintableString (SIZE (1..MAX)),
     *    universalString             UniversalString (SIZE (1..MAX)),
     *    utf8String                  UTF8String (SIZE (1..MAX)),
     *    bmpString                   BMPString (SIZE (1..MAX))  }
     * </pre>
     */
    public ASN1Primitive toASN1Primitive()
    {
        return ((ASN1Encodable)string).toASN1Primitive();
    }
}
