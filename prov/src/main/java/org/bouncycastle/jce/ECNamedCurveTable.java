package org.bouncycastle.jce;

import java.util.Enumeration;
import java.util.Vector;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTNamedCurves;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.teletrust.TeleTrusTNamedCurves;
import org.bouncycastle.asn1.x9.X962NamedCurves;
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
        X9ECParameters  ecP = X962NamedCurves.getByName(name);
        if (ecP == null)
        {
            try
            {
                ecP = X962NamedCurves.getByOID(new ASN1ObjectIdentifier(name));
            }
            catch (IllegalArgumentException e)
            {
                // ignore - not an oid
            }
        }
        
        if (ecP == null)
        {
            ecP = SECNamedCurves.getByName(name);
            if (ecP == null)
            {
                try
                {
                    ecP = SECNamedCurves.getByOID(new ASN1ObjectIdentifier(name));
                }
                catch (IllegalArgumentException e)
                {
                    // ignore - not an oid
                }
            }
        }

        if (ecP == null)
        {
            ecP = TeleTrusTNamedCurves.getByName(name);
            if (ecP == null)
            {
                try
                {
                    ecP = TeleTrusTNamedCurves.getByOID(new ASN1ObjectIdentifier(name));
                }
                catch (IllegalArgumentException e)
                {
                    // ignore - not an oid
                }
            }
        }

        if (ecP == null)
        {
            ecP = NISTNamedCurves.getByName(name);
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
        Vector v = new Vector();
        
        addEnumeration(v, X962NamedCurves.getNames());
        addEnumeration(v, SECNamedCurves.getNames());
        addEnumeration(v, NISTNamedCurves.getNames());
        addEnumeration(v, TeleTrusTNamedCurves.getNames());

        return v.elements();
    }

    private static void addEnumeration(
        Vector v, 
        Enumeration e)
    {
        while (e.hasMoreElements())
        {
            v.addElement(e.nextElement());
        }
    }
}
