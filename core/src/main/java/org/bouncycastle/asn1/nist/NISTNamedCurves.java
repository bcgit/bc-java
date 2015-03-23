package org.bouncycastle.asn1.nist;

import java.util.Enumeration;
import java.util.Hashtable;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.sec.SECObjectIdentifiers;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.util.Strings;

/**
 * Utility class for fetching curves using their NIST names as published in FIPS-PUB 186-3
 */
public class NISTNamedCurves
{
    static final Hashtable objIds = new Hashtable();
    static final Hashtable names = new Hashtable();

    static void defineCurveAlias(String name, ASN1ObjectIdentifier oid)
    {
        objIds.put(name.toUpperCase(), oid);
        names.put(oid, name);
    }

    static
    {
        defineCurveAlias("B-163", SECObjectIdentifiers.sect163r2);
        defineCurveAlias("B-233", SECObjectIdentifiers.sect233r1);
        defineCurveAlias("B-283", SECObjectIdentifiers.sect283r1);
        defineCurveAlias("B-409", SECObjectIdentifiers.sect409r1);
        defineCurveAlias("B-571", SECObjectIdentifiers.sect571r1);

        defineCurveAlias("K-163", SECObjectIdentifiers.sect163k1);
        defineCurveAlias("K-233", SECObjectIdentifiers.sect233k1);
        defineCurveAlias("K-283", SECObjectIdentifiers.sect283k1);
        defineCurveAlias("K-409", SECObjectIdentifiers.sect409k1);
        defineCurveAlias("K-571", SECObjectIdentifiers.sect571k1);

        defineCurveAlias("P-192", SECObjectIdentifiers.secp192r1);
        defineCurveAlias("P-224", SECObjectIdentifiers.secp224r1);
        defineCurveAlias("P-256", SECObjectIdentifiers.secp256r1);
        defineCurveAlias("P-384", SECObjectIdentifiers.secp384r1);
        defineCurveAlias("P-521", SECObjectIdentifiers.secp521r1);
    }

    public static X9ECParameters getByName(
        String  name)
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
        ASN1ObjectIdentifier  oid)
    {
        return SECNamedCurves.getByOID(oid);
    }

    /**
     * return the object identifier signified by the passed in name. Null
     * if there is no object identifier associated with name.
     *
     * @return the object identifier associated with name, if present.
     */
    public static ASN1ObjectIdentifier getOID(
        String  name)
    {
        return (ASN1ObjectIdentifier)objIds.get(Strings.toUpperCase(name));
    }

    /**
     * return the named curve name represented by the given object identifier.
     */
    public static String getName(
        ASN1ObjectIdentifier  oid)
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
