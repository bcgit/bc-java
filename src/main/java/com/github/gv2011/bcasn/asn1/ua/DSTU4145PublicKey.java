package com.github.gv2011.bcasn.asn1.ua;

import com.github.gv2011.bcasn.asn1.ASN1Object;
import com.github.gv2011.bcasn.asn1.ASN1OctetString;
import com.github.gv2011.bcasn.asn1.ASN1Primitive;
import com.github.gv2011.bcasn.asn1.DEROctetString;
import com.github.gv2011.bcasn.math.ec.ECPoint;

public class DSTU4145PublicKey
    extends ASN1Object
{

    private ASN1OctetString pubKey;

    public DSTU4145PublicKey(ECPoint pubKey)
    {
        // We always use big-endian in parameter encoding
        this.pubKey = new DEROctetString(DSTU4145PointEncoder.encodePoint(pubKey));
    }

    private DSTU4145PublicKey(ASN1OctetString ocStr)
    {
        pubKey = ocStr;
    }

    public static DSTU4145PublicKey getInstance(Object obj)
    {
        if (obj instanceof DSTU4145PublicKey)
        {
            return (DSTU4145PublicKey)obj;
        }

        if (obj != null)
        {
            return new DSTU4145PublicKey(ASN1OctetString.getInstance(obj));
        }

        return null;
    }

    public ASN1Primitive toASN1Primitive()
    {
        return pubKey;
    }

}
