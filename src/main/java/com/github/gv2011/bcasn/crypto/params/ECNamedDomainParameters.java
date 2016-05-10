package com.github.gv2011.bcasn.crypto.params;

import java.math.BigInteger;

import com.github.gv2011.bcasn.asn1.ASN1ObjectIdentifier;
import com.github.gv2011.bcasn.math.ec.ECCurve;
import com.github.gv2011.bcasn.math.ec.ECPoint;

public class ECNamedDomainParameters
    extends ECDomainParameters
{
    private ASN1ObjectIdentifier name;

    public ECNamedDomainParameters(ASN1ObjectIdentifier name, ECCurve curve, ECPoint G, BigInteger n)
    {
        this(name, curve, G, n, null, null);
    }

    public ECNamedDomainParameters(ASN1ObjectIdentifier name, ECCurve curve, ECPoint G, BigInteger n, BigInteger h)
    {
        this(name, curve, G, n, h, null);
    }

    public ECNamedDomainParameters(ASN1ObjectIdentifier name, ECCurve curve, ECPoint G, BigInteger n, BigInteger h, byte[] seed)
    {
        super(curve, G, n, h, seed);

        this.name = name;
    }

    public ASN1ObjectIdentifier getName()
    {
        return name;
    }
}
