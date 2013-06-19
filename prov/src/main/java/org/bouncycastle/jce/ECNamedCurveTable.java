package org.bouncycastle.jce;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;


/**
 * Extension on org.bouncycastle.asn1.x9.ECNamedCurveTable sharing same
 * static methods and datasets.
 * <p>
 * Pickup JCE resident ECNamedCurveParameterSpec for named curve.
 */
public class ECNamedCurveTable extends org.bouncycastle.asn1.x9.ECNamedCurveTable {

    /**
     * return a parameter spec representing the passed in named
     * curve. The routine returns null if the curve is not present.
     * 
     * @param name the name of the curve requested
     * @return a parameter spec for the curve, null if it is not available.
     */
    public static ECNamedCurveParameterSpec getParameterSpec( final String  name )
    {
        X9ECParameters  ecP = getByName(name);
        if (ecP == null) {
            try {
                ecP = getByOID(new ASN1ObjectIdentifier(name));
            }
            catch (IllegalArgumentException e) {
                // ignore - not an oid
            }
        }
        
        if (ecP == null) {
            return null; // Nothing found
        }

        return new ECNamedCurveParameterSpec( name,
                                              ecP.getCurve(),
                                              ecP.getG(),
                                              ecP.getN(),
                                              ecP.getH(),
                                              ecP.getSeed());
    }

    /**
     * return a parameter spec representing the passed in named
     * curve. The routine returns null if the curve is not present.
     * 
     * @param oid the OID of the curve requested
     * @return a parameter spec for the curve, null if it is not available.
     */
    public static ECNamedCurveParameterSpec getParameterSpec( final ASN1ObjectIdentifier oid )
    {
        final X9ECParameters ecP = getByOID(oid);
        if (ecP == null) {
            return null; // Nothing found
        }

        final String name = getName(oid);

        return new ECNamedCurveParameterSpec( name,
                                              ecP.getCurve(),
                                              ecP.getG(),
                                              ecP.getN(),
                                              ecP.getH(),
                                              ecP.getSeed());
    }
}
