package org.bouncycastle.asn1.x9;

import java.util.Enumeration;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Vector;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cryptopro.ECGOST3410NamedCurves;
import org.bouncycastle.asn1.nist.NISTNamedCurves;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.teletrust.TeleTrusTNamedCurves;
import org.bouncycastle.asn1.ua.DSTU4145NamedCurves;
import org.bouncycastle.asn1.x9.X962NamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.params.ECDomainParameters;

/**
 * A general class that reads all X9.62 style EC curve tables.
 *
 * TODO: ECGOST3410NamedCurves + DSTU4145NamedCurves need to be updated and included here.
 */
public class ECNamedCurveTable
{

    // Runtime registered new named/OIDs/parameters 

    private static final HashMap objIds = new HashMap(); // String -> OID
    private static final HashMap names  = new HashMap(); // OID -> String
    private static final HashMap params = new HashMap(); // OID -> X9ECParameters


    /*
      // pre-loading in init would be nice, except that different
      // name sources have different styles of lookups -- some
      // canonicalize to lowercase, at least one to uppercase.

    private static Boolean initDone = Boolean.FALSE;

    private static void _init()
    {
        synchronized (initDone) {
            if (!initDone) {
                for (final Enumeration en = X962NamedCurves.getNames(); en.hasMoreElements() ; ) {
                    // These names are lowercase..
                    final String name = (String)en.nextElement();
                    final ASN1ObjectIdentifier oid = X962NamedCurves.getOID(name);

                    objIds.put(name, oid);
                    names.put(oid,name);

                    final X9ECParameters xp = X962NamedCurves.getByOID(oid);

                    params.put(oid, xp);
                }
                for (final Enumeration en = SECNamedCurves.getNames(); en.hasMoreElements() ; ) {
                    // These names are lowercase..
                    final String name = (String)en.nextElement();
                    final ASN1ObjectIdentifier oid = SECNamedCurves.getOID(name);

                    objIds.put(name, oid);
                    names.put(oid,name);

                    final X9ECParameters xp = SECNamedCurves.getByOID(oid);

                    params.put(oid, xp);
                }
                for (final Enumeration en = TeleTrusTNamedCurves.getNames(); en.hasMoreElements() ; ) {
                    // These names are lowercase..
                    final String name = (String)en.nextElement();
                    final ASN1ObjectIdentifier oid = TeleTrusTNamedCurves.getOID(name);

                    objIds.put(name, oid);
                    names.put(oid,name);

                    final X9ECParameters xp = TeleTrusTNamedCurves.getByOID(oid);

                    params.put(oid, xp);
                }
                for (final Enumeration en = NISTNamedCurves.getNames(); en.hasMoreElements() ; ) {
                    // These names are UPPERCASE..
                    final String name = ((String)en.nextElement()).toLowerCase();
                    final ASN1ObjectIdentifier oid = NISTNamedCurves.getOID(name);

                    objIds.put(name, oid);
                    names.put(oid,name);

                    final X9ECParameters xp = NISTNamedCurves.getByOID(oid);

                    params.put(oid, xp);
                }


                initDone = Boolean.TRUE;
            }
        }
    }
    */

    /**
     * return a X9ECParameters object representing the passed in named
     * curve. The routine returns null if the curve is not present.
     *
     * @param name the name of the curve requested
     * @return an X9ECParameters object or null if the curve is not available.
     */
    public static X9ECParameters getByName( final String name )
    {
        X9ECParameters   ecP = X962NamedCurves.getByName(name);
        if (ecP == null) ecP = SECNamedCurves.getByName(name);
        if (ecP == null) ecP = TeleTrusTNamedCurves.getByName(name);
        if (ecP == null) ecP = NISTNamedCurves.getByName(name);
        // if (ecP == null) {
        //   ECDomainParameters dp = ECGOST3410NamedCurves.getByName(name);
        //   if (dp != null) ecP = new X9ECParameters(dp); // TODO - modify ECGOST.. to be compatible with all others
        // }

        if (ecP == null) ecP = _getByName(name);

        return ecP;
    }

    private static X9ECParameters _getByName( final String name )
    {
        final ASN1ObjectIdentifier oid;
        synchronized (objIds) {
            oid = (ASN1ObjectIdentifier)objIds.get(name.toLowerCase());
        }

        if (oid != null) {
            return _getByOID(oid);
        }

        return null;
    }


    /**
     * return a X9ECParameters object representing the passed in named
     * curve.
     *
     * @param oid the object id of the curve requested
     * @return an X9ECParameters object or null if the curve is not available.
     */
    public static X9ECParameters getByOID( final ASN1ObjectIdentifier oid )
    {
        X9ECParameters   ecP = X962NamedCurves.getByOID(oid);
        if (ecP == null) ecP = SECNamedCurves.getByOID(oid);
        if (ecP == null) ecP = TeleTrusTNamedCurves.getByOID(oid);

        // NISTNamedCurves are aliases of SECNamedCurves, thus no need to OID lookup

        // if (ecP == null) {
        //    ECDomainParameters dp = ECGOST3410NamedCurves.getByOID(oid);
        //    if (dp != null) ecP = new X9ECParameters(dp); // TODO - modify ECGOST.. to be compatible with all others
        // }

        if (ecP == null) ecP = _getByOID(oid);

        return ecP;
    }


    private static X9ECParameters _getByOID( final ASN1ObjectIdentifier oid )
    {
        synchronized (params) {
            return (X9ECParameters)params.get(oid);
        }
    }


    /**
     * Return an enumeration of the names of the available curves.
     * This enumeration is safe against modifications of the storage.
     *
     * @return an enumeration of the names of the available curves.
     */
    public static Enumeration getNames()
    {
        final Vector v = new Vector();

        addEnumeration(v, X962NamedCurves.getNames());
        addEnumeration(v, SECNamedCurves.getNames());
        addEnumeration(v, NISTNamedCurves.getNames());
        addEnumeration(v, TeleTrusTNamedCurves.getNames());
        // addEnumeration(v, ECGOST3410NamedCurves.getNames());

        synchronized (objIds) {
            final Iterator keys = objIds.keySet().iterator();
            while (keys.hasNext()) {
                v.addElement(keys.next());
            }
        }

        return v.elements();
    }

    private static void addEnumeration( final Vector v,
                                        final Enumeration e )
    {
        while (e.hasMoreElements()) {
            v.addElement(e.nextElement());
        }
    }

    /**
     * return the object identifier signified by the passed in name. Null
     * if there is no object identifier associated with name.
     *
     * @return the object identifier associated with name, if present.
     */
    public static ASN1ObjectIdentifier getOID( final String name )
    {
        ASN1ObjectIdentifier oid = X962NamedCurves.getOID(name);
        if (oid == null)     oid = SECNamedCurves.getOID(name);
        if (oid == null)     oid = TeleTrusTNamedCurves.getOID(name);
        if (oid == null)     oid = NISTNamedCurves.getOID(name);
        // if (oid == null)     oid = ECGOST3410NamedCurves.getOID(name);

        if (oid == null) {
            synchronized (objIds) {
                oid = (ASN1ObjectIdentifier)objIds.get(name.toLowerCase());
            }
        }
        return oid;
    }

    /**
     * return the named curve name represented by the given object identifier.
     */
    public static String getName( final ASN1ObjectIdentifier oid )
    {
        String            name = X962NamedCurves.getName(oid);
        if (name == null) name = SECNamedCurves.getName(oid);
        if (name == null) name = TeleTrusTNamedCurves.getName(oid);
        if (name == null) name = NISTNamedCurves.getName(oid);
        // if (name == null) name = ECGOST3410NamedCurves.getName(oid);
        if (name == null) {
            synchronized (names) {
                name = (String)names.get(oid);
            }
        }
        return name;
    }


    /**
     * Brainpool Prime curves have special getter for their OIDs
     */

    public static ASN1ObjectIdentifier getOID( final short curvesize, final boolean twisted )
    {
        return TeleTrusTNamedCurves.getOID(curvesize, twisted);
    }



    /**
     * Register new curve to system wide set
     */
    public static void register(final String name, final ASN1ObjectIdentifier oid, final X9ECParameters xp)
    {
        synchronized(names) {
            names.put(oid, name);
        }
        synchronized(objIds) {
            objIds.put(name, oid);
        }
        synchronized(params) {
            params.put(oid, xp);
        }
    }
}
