package org.bouncycastle.asn1.cmp;

import java.io.IOException;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.BERTags;
import org.bouncycastle.asn1.x509.AttributeCertificate;
import org.bouncycastle.asn1.x509.Certificate;

/**
 * OOBCert ::= CMPCertificate
 */
public class OOBCert
    extends CMPCertificate
{

    public OOBCert(AttributeCertificate x509v2AttrCert)
    {
        super(1, x509v2AttrCert);
    }

    public OOBCert(int type, ASN1Object otherCert)
    {
        super(type, otherCert);
    }

    public OOBCert(Certificate x509v3PKCert)
    {
        super(x509v3PKCert);
    }

    public static OOBCert getInstance(ASN1TaggedObject ato, boolean isExplicit)
    {
        if (ato != null)
        {
            if (isExplicit)
            {
                return OOBCert.getInstance(ato.getExplicitBaseObject());
            }
            else
            {
                throw new IllegalArgumentException("tag must be explicit");
            }
        }
        return null;
    }

    public static OOBCert getInstance(Object o)
    {

        if (o == null || o instanceof OOBCert)
        {
            return (OOBCert)o;
        }

        if (o instanceof CMPCertificate)
        {
            try
            {
                return getInstance(((CMPCertificate)o).getEncoded());
            }
            catch (IOException e)
            {
                throw new IllegalArgumentException(e.getMessage(), e);
            }
        }

        if (o instanceof byte[])
        {
            try
            {
                o = ASN1Primitive.fromByteArray((byte[])o);
            }
            catch (IOException e)
            {
                throw new IllegalArgumentException("Invalid encoding in OOBCert");
            }
        }

        if (o instanceof ASN1Sequence)
        {
            return new OOBCert(Certificate.getInstance(o));
        }

        if (o instanceof ASN1TaggedObject)
        {
            ASN1TaggedObject taggedObject = ASN1TaggedObject.getInstance(o, BERTags.CONTEXT_SPECIFIC);

            return new OOBCert(taggedObject.getTagNo(), taggedObject.getExplicitBaseObject());
        }

        throw new IllegalArgumentException("Invalid object: " + o.getClass().getName());
    }

}
