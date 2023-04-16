package org.bouncycastle.asn1.x500;

import org.bouncycastle.asn1.ASN1BMPString;
import org.bouncycastle.asn1.ASN1Choice;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1PrintableString;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.ASN1T61String;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.ASN1UTF8String;
import org.bouncycastle.asn1.ASN1UniversalString;
import org.bouncycastle.asn1.DERUTF8String;

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

        if (o instanceof ASN1T61String)
        {
            return new DirectoryString((ASN1T61String)o);
        }

        if (o instanceof ASN1PrintableString)
        {
            return new DirectoryString((ASN1PrintableString)o);
        }

        if (o instanceof ASN1UniversalString)
        {
            return new DirectoryString((ASN1UniversalString)o);
        }

        if (o instanceof ASN1UTF8String)
        {
            return new DirectoryString((ASN1UTF8String)o);
        }

        if (o instanceof ASN1BMPString)
        {
            return new DirectoryString((ASN1BMPString)o);
        }

        throw new IllegalArgumentException("illegal object in getInstance: " + o.getClass().getName());
    }

    public static DirectoryString getInstance(ASN1TaggedObject o, boolean explicit)
    {
        if (!explicit)
        {
            throw new IllegalArgumentException("choice item must be explicitly tagged");
        }

        return getInstance(o.getExplicitBaseObject());
    }

    private DirectoryString(
        ASN1T61String string)
    {
        this.string = string;
    }

    private DirectoryString(
        ASN1PrintableString string)
    {
        this.string = string;
    }

    private DirectoryString(
        ASN1UniversalString string)
    {
        this.string = string;
    }

    private DirectoryString(
        ASN1UTF8String string)
    {
        this.string = string;
    }

    private DirectoryString(
        ASN1BMPString string)
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
