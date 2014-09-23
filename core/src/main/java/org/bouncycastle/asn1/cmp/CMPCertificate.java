package org.bouncycastle.asn1.cmp;

import java.io.IOException;

import org.bouncycastle.asn1.ASN1Choice;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x509.AttributeCertificate;
import org.bouncycastle.asn1.x509.Certificate;

public class CMPCertificate
    extends ASN1Object
    implements ASN1Choice
{
    private Certificate x509v3PKCert;

    private int        otherTagValue;
    private ASN1Object otherCert;

    /**
     * Note: the addition of attribute certificates is a BC extension. If you use this constructor they
     * will be added with a tag value of 1.
     * @deprecated use (type. otherCert) constructor
     */
    public CMPCertificate(AttributeCertificate x509v2AttrCert)
    {
        this(1, x509v2AttrCert);
    }

    /**
     * Note: the addition of other certificates is a BC extension. If you use this constructor they
     * will be added with an explicit tag value of type.
     *
     * @param type the type of the certificate (used as a tag value).
     * @param otherCert the object representing the certificate
     */
    public CMPCertificate(int type, ASN1Object otherCert)
    {
        this.otherTagValue = type;
        this.otherCert = otherCert;
    }

    public CMPCertificate(Certificate x509v3PKCert)
    {
        if (x509v3PKCert.getVersionNumber() != 3)
        {
            throw new IllegalArgumentException("only version 3 certificates allowed");
        }

        this.x509v3PKCert = x509v3PKCert;
    }

    public static CMPCertificate getInstance(Object o)
    {
        if (o == null || o instanceof CMPCertificate)
        {
            return (CMPCertificate)o;
        }

        if (o instanceof byte[])
        {
            try
            {
                o = ASN1Primitive.fromByteArray((byte[])o);
            }
            catch (IOException e)
            {
                throw new IllegalArgumentException("Invalid encoding in CMPCertificate");
            }
        }

        if (o instanceof ASN1Sequence)
        {
            return new CMPCertificate(Certificate.getInstance(o));
        }

        if (o instanceof ASN1TaggedObject)
        {
            ASN1TaggedObject taggedObject = (ASN1TaggedObject)o;

            return new CMPCertificate(taggedObject.getTagNo(), taggedObject.getObject());
        }

        throw new IllegalArgumentException("Invalid object: " + o.getClass().getName());
    }

    public boolean isX509v3PKCert()
    {
         return x509v3PKCert != null;
    }

    public Certificate getX509v3PKCert()
    {
        return x509v3PKCert;
    }

    /**
     * Return an AttributeCertificate interpretation of otherCert.
     * @deprecated use getOtherCert and getOtherTag to make sure message is really what it should be.
     *
     * @return  an AttributeCertificate
     */
    public AttributeCertificate getX509v2AttrCert()
    {
        return AttributeCertificate.getInstance(otherCert);
    }

    public int getOtherCertTag()
    {
        return otherTagValue;
    }

    public ASN1Object getOtherCert()
    {
        return otherCert;
    }

    /**
     * <pre>
     * CMPCertificate ::= CHOICE {
     *            x509v3PKCert    Certificate
     *            otherCert      [tag] EXPLICIT ANY DEFINED BY tag
     *  }
     * </pre>
     * Note: the addition of the explicit tagging is a BC extension. We apologise for the warped syntax, but hopefully you get the idea.
     *
     * @return a basic ASN.1 object representation.
     */
    public ASN1Primitive toASN1Primitive()
    {
        if (otherCert != null)
        {        // explicit following CMP conventions
            return new DERTaggedObject(true, otherTagValue, otherCert);
        }

        return x509v3PKCert.toASN1Primitive();
    }
}
