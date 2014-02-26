package org.bouncycastle.crypto.ec;

import java.util.Enumeration;
import java.util.Hashtable;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.sec.SECObjectIdentifiers;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.asn1.x9.X9ECParametersHolder;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.custom.sec.SecP192K1Curve;
import org.bouncycastle.math.ec.custom.sec.SecP192R1Curve;
import org.bouncycastle.math.ec.custom.sec.SecP224K1Curve;
import org.bouncycastle.math.ec.custom.sec.SecP224R1Curve;
import org.bouncycastle.math.ec.custom.sec.SecP256K1Curve;
import org.bouncycastle.math.ec.custom.sec.SecP256R1Curve;
import org.bouncycastle.math.ec.custom.sec.SecP384R1Curve;
import org.bouncycastle.math.ec.custom.sec.SecP521R1Curve;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;

public class CustomNamedCurves
{
    private static ECCurve configureCurve(ECCurve curve)
    {
        return curve;
    }

    /*
     * secp192k1
     */
    static X9ECParametersHolder secp192k1 = new X9ECParametersHolder()
    {
        protected X9ECParameters createParameters()
        {
            byte[] S = null;
            ECCurve curve = configureCurve(new SecP192K1Curve());
            ECPoint G = curve.decodePoint(Hex.decode("04"
                + "DB4FF10EC057E9AE26B07D0280B7F4341DA5D1B1EAE06C7D"
                + "9B2F2F6D9C5628A7844163D015BE86344082AA88D95E2F9D"));
            return new X9ECParameters(curve, G, curve.getOrder(), curve.getCofactor(), S);
        }
    };

    /*
     * secp192r1
     */
    static X9ECParametersHolder secp192r1 = new X9ECParametersHolder()
    {
        protected X9ECParameters createParameters()
        {
            byte[] S = Hex.decode("3045AE6FC8422F64ED579528D38120EAE12196D5");
            ECCurve curve = configureCurve(new SecP192R1Curve());
            ECPoint G = curve.decodePoint(Hex.decode("04"
                + "188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012"
                + "07192B95FFC8DA78631011ED6B24CDD573F977A11E794811"));
            return new X9ECParameters(curve, G, curve.getOrder(), curve.getCofactor(), S);
        }
    };

    /*
     * secp224k1
     */
    static X9ECParametersHolder secp224k1 = new X9ECParametersHolder()
    {
        protected X9ECParameters createParameters()
        {
            byte[] S = null;
            ECCurve curve = configureCurve(new SecP224K1Curve());
            ECPoint G = curve.decodePoint(Hex.decode("04"
                + "A1455B334DF099DF30FC28A169A467E9E47075A90F7E650EB6B7A45C"
                + "7E089FED7FBA344282CAFBD6F7E319F7C0B0BD59E2CA4BDB556D61A5"));
            return new X9ECParameters(curve, G, curve.getOrder(), curve.getCofactor(), S);
        }
    };

    /*
     * secp224r1
     */
    static X9ECParametersHolder secp224r1 = new X9ECParametersHolder()
    {
        protected X9ECParameters createParameters()
        {
            byte[] S = Hex.decode("BD71344799D5C7FCDC45B59FA3B9AB8F6A948BC5");
            ECCurve curve = configureCurve(new SecP224R1Curve());
            ECPoint G = curve.decodePoint(Hex.decode("04"
                + "B70E0CBD6BB4BF7F321390B94A03C1D356C21122343280D6115C1D21"
                + "BD376388B5F723FB4C22DFE6CD4375A05A07476444D5819985007E34"));
            return new X9ECParameters(curve, G, curve.getOrder(), curve.getCofactor(), S);
        }
    };

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

    /*
     * secp384r1
     */
    static X9ECParametersHolder secp384r1 = new X9ECParametersHolder()
    {
        protected X9ECParameters createParameters()
        {
            byte[] S = Hex.decode("A335926AA319A27A1D00896A6773A4827ACDAC73");
            ECCurve curve = configureCurve(new SecP384R1Curve());
            ECPoint G = curve.decodePoint(Hex.decode("04"
                + "AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7"
                + "3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F"));
            return new X9ECParameters(curve, G, curve.getOrder(), curve.getCofactor(), S);
        }
    };

    /*
     * secp521r1
     */
    static X9ECParametersHolder secp521r1 = new X9ECParametersHolder()
    {
        protected X9ECParameters createParameters()
        {
            byte[] S = Hex.decode("D09E8800291CB85396CC6717393284AAA0DA64BA");
            ECCurve curve = configureCurve(new SecP521R1Curve());
            ECPoint G = curve.decodePoint(Hex.decode("04"
                + "00C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66"
                + "011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650"));
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
        defineCurve("secp192k1", SECObjectIdentifiers.secp192k1, secp192k1);
        defineCurve("secp192r1", SECObjectIdentifiers.secp192r1, secp192r1);
        defineCurve("secp224k1", SECObjectIdentifiers.secp224k1, secp224k1);
        defineCurve("secp224r1", SECObjectIdentifiers.secp224r1, secp224r1);
        defineCurve("secp256k1", SECObjectIdentifiers.secp256k1, secp256k1);
        defineCurve("secp256r1", SECObjectIdentifiers.secp256r1, secp256r1);
        defineCurve("secp384r1", SECObjectIdentifiers.secp384r1, secp384r1);
        defineCurve("secp521r1", SECObjectIdentifiers.secp521r1, secp521r1);

        objIds.put(Strings.toLowerCase("P-192"), SECObjectIdentifiers.secp192r1);
        objIds.put(Strings.toLowerCase("P-224"), SECObjectIdentifiers.secp224r1);
        objIds.put(Strings.toLowerCase("P-256"), SECObjectIdentifiers.secp256r1);
        objIds.put(Strings.toLowerCase("P-384"), SECObjectIdentifiers.secp384r1);
        objIds.put(Strings.toLowerCase("P-521"), SECObjectIdentifiers.secp521r1);
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
