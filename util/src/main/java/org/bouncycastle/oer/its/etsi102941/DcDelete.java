package org.bouncycastle.oer.its.etsi102941;

import org.bouncycastle.asn1.ASN1IA5String;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERIA5String;

public class DcDelete
    extends ASN1Object
{
    private final String url;

    public DcDelete(String url)
    {
        this.url = url;
    }

    private DcDelete(ASN1IA5String url)
    {
        this.url = url.getString();
    }

    public static DcDelete getInstance(Object o)
    {
        if (o instanceof DcDelete)
        {
            return (DcDelete)o;
        }

        if (o != null)
        {
            return new DcDelete(ASN1IA5String.getInstance(o));
        }

        return null;
    }

    public ASN1Primitive toASN1Primitive()
    {
        return new DERIA5String(url);
    }

    public String getUrl()
    {
        return url;
    }
}
