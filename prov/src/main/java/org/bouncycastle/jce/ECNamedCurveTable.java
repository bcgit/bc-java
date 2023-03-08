package org.bouncycastle.jce;

import java.util.Enumeration;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;

/**
 * a table of locally supported named curves.
 */
public class ECNamedCurveTable
{
    /**
     * return a parameter spec representing the passed in named
     * curve. The routine returns null if the curve is not present.
     * 
     * @param name the name of the curve requested
     * @return a parameter spec for the curve, null if it is not available.
     */
    public static ECNamedCurveParameterSpec getParameterSpec(
        String  name)
    {
        ASN1ObjectIdentifier oid;
        try
        {
            oid = possibleOID(name) ? new ASN1ObjectIdentifier(name) : null;
        }
        catch (IllegalArgumentException e)
        {
            oid = null;
        }

        X9ECParameters ecP;
        if (oid != null)
        {
            ecP = org.bouncycastle.crypto.ec.CustomNamedCurves.getByOID(oid);
        }
        else
        {
            ecP = org.bouncycastle.crypto.ec.CustomNamedCurves.getByName(name);
        }

        if (ecP == null)
        {
            if (oid != null)
            {
                ecP = org.bouncycastle.asn1.x9.ECNamedCurveTable.getByOID(oid);
            }
            else
            {
                ecP = org.bouncycastle.asn1.x9.ECNamedCurveTable.getByName(name);
            }
        }

        if (ecP == null)
        {
            return null;
        }

        return new ECNamedCurveParameterSpec(
                                        name,
                                        ecP.getCurve(),
                                        ecP.getG(),
                                        ecP.getN(),
                                        ecP.getH(),
                                        ecP.getSeed());
    }

    /**
     * return an enumeration of the names of the available curves.
     *
     * @return an enumeration of the names of the available curves.
     */
    public static Enumeration getNames()
    {
        return org.bouncycastle.asn1.x9.ECNamedCurveTable.getNames();
    }

    private static boolean possibleOID(
        String identifier)
    {
        if (identifier.length() < 3 || identifier.charAt(1) != '.')
        {
            return false;
        }

        char first = identifier.charAt(0);
        if (first < '0' || first > '2')
        {
            return false;
        }

        return true;
    }
}
