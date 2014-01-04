package org.bouncycastle.asn1.sec;

import java.util.Enumeration;
import java.util.Hashtable;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.asn1.x9.X9ECParametersHolder;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.custom.sec.SecP256K1Curve;
import org.bouncycastle.math.ec.custom.sec.SecP256R1Curve;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;

public class SECCustomNamedCurves
{
    private static ECCurve configureCurve(ECCurve curve)
    {
        return curve;
    }

    /*
     * secp256k1
     */
    static X9ECParametersHolder secp256k1 = new X9ECParametersHolder()
    {
        protected X9ECParameters createParameters()
        {
            byte[] S = null;
            ECCurve curve = configureCurve(new SecP256K1Curve());
            ECPoint G = curve.decodePoint(Hex.decode("04"
                + "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
                + "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8"));
            return new X9ECParameters(curve, G, curve.getOrder(), curve.getCofactor(), S);
        }
    };

    /*
     * secp256r1
     */
    static X9ECParametersHolder secp256r1 = new X9ECParametersHolder()
    {
        protected X9ECParameters createParameters()
        {
            byte[] S = Hex.decode("C49D360886E704936A6678E1139D26B7819F7E90");
            ECCurve curve = configureCurve(new SecP256R1Curve());
            ECPoint G = curve.decodePoint(Hex.decode("04"
                + "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296"
                + "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5"));
            return new X9ECParameters(curve, G, curve.getOrder(), curve.getCofactor(), S);
        }
    };

    static final Hashtable objIds = new Hashtable();
    static final Hashtable curves = new Hashtable();
    static final Hashtable names = new Hashtable();

    static void defineCurve(String name, ASN1ObjectIdentifier oid, X9ECParametersHolder holder)
    {
        objIds.put(name, oid);
        names.put(oid, name);
        curves.put(oid, holder);
    }

    static
    {
        defineCurve("secp256k1", SECObjectIdentifiers.secp256k1, secp256k1);
        defineCurve("secp256r1", SECObjectIdentifiers.secp256r1, secp256r1);

        objIds.put(Strings.toLowerCase("P-256"), SECObjectIdentifiers.secp256r1);
    }

    public static X9ECParameters getByName(String name)
    {
        ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier)objIds.get(Strings.toLowerCase(name));
        return oid == null ? null : getByOID(oid);
    }

    /**
     * return the X9ECParameters object for the named curve represented by the passed in object
     * identifier. Null if the curve isn't present.
     * 
     * @param oid
     *            an object identifier representing a named curve, if present.
     */
    public static X9ECParameters getByOID(ASN1ObjectIdentifier oid)
    {
        X9ECParametersHolder holder = (X9ECParametersHolder)curves.get(oid);
        return holder == null ? null : holder.getParameters();
    }

    /**
     * return the object identifier signified by the passed in name. Null if there is no object
     * identifier associated with name.
     * 
     * @return the object identifier associated with name, if present.
     */
    public static ASN1ObjectIdentifier getOID(String name)
    {
        return (ASN1ObjectIdentifier)objIds.get(Strings.toLowerCase(name));
    }

    /**
     * return the named curve name represented by the given object identifier.
     */
    public static String getName(ASN1ObjectIdentifier oid)
    {
        return (String)names.get(oid);
    }

    /**
     * returns an enumeration containing the name strings for curves contained in this structure.
     */
    public static Enumeration getNames()
    {
        return objIds.keys();
    }
}
