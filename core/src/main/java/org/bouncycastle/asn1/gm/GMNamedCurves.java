package org.bouncycastle.asn1.gm;

import java.math.BigInteger;
import java.util.Enumeration;
import java.util.Hashtable;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.asn1.x9.X9ECParametersHolder;
import org.bouncycastle.asn1.x9.X9ECPoint;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;

/**
 * Chinese standard GM named curves.
 */
public class GMNamedCurves
{
    private static ECCurve configureCurve(ECCurve curve)
    {
        return curve;
    }

    private static BigInteger fromHex(
        String hex)
    {
        return new BigInteger(1, Hex.decode(hex));
    }

    /*
     * SM2SysParams
     */
    static X9ECParametersHolder SM2SysParams = new X9ECParametersHolder()
    {
        protected X9ECParameters createParameters()
        {

            BigInteger p = fromHex("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF");
            BigInteger a = fromHex("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC");
            BigInteger b = fromHex("28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93");
            byte[] S = null;
            BigInteger n = fromHex("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123");
            BigInteger h = BigInteger.valueOf(1);

            ECCurve curve = configureCurve(new ECCurve.Fp(p, a, b, n, h));
            X9ECPoint G = new X9ECPoint(curve, Hex.decode("04"
                + "32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7"
                + "BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0"));

            return new X9ECParameters(curve, G, n, h, S);
        }
    };


    static final Hashtable objIds = new Hashtable();
    static final Hashtable curves = new Hashtable();
    static final Hashtable names = new Hashtable();

    static void defineCurve(String name, ASN1ObjectIdentifier oid, X9ECParametersHolder holder)
    {
        objIds.put(Strings.toLowerCase(name), oid);
        names.put(oid, name);
        curves.put(oid, holder);
    }

    static
    {
        defineCurve("SM2SysParams", GMObjectIdentifiers.SM2_Elliptic_Curve_Cryptography, SM2SysParams);
    }

    public static X9ECParameters getByName(
        String name)
    {
        ASN1ObjectIdentifier oid = getOID(name);
        return oid == null ? null : getByOID(oid);
    }

    /**
     * return the X9ECParameters object for the named curve represented by
     * the passed in object identifier. Null if the curve isn't present.
     *
     * @param oid an object identifier representing a named curve, if present.
     */
    public static X9ECParameters getByOID(
        ASN1ObjectIdentifier oid)
    {
        X9ECParametersHolder holder = (X9ECParametersHolder)curves.get(oid);
        return holder == null ? null : holder.getParameters();
    }

    /**
     * return the object identifier signified by the passed in name. Null
     * if there is no object identifier associated with name.
     *
     * @return the object identifier associated with name, if present.
     */
    public static ASN1ObjectIdentifier getOID(
        String name)
    {
        return (ASN1ObjectIdentifier)objIds.get(Strings.toLowerCase(name));
    }

    /**
     * return the named curve name represented by the given object identifier.
     */
    public static String getName(
        ASN1ObjectIdentifier oid)
    {
        return (String)names.get(oid);
    }

    /**
     * returns an enumeration containing the name strings for curves
     * contained in this structure.
     */
    public static Enumeration getNames()
    {
        return names.elements();
    }
}

