package org.bouncycastle.crypto.util;

import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTNamedCurves;
import org.bouncycastle.asn1.sec.SECObjectIdentifiers;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECNamedDomainParameters;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.util.Strings;

public class SSHNamedCurves
{
    private static final Map<ASN1ObjectIdentifier, String> oidToName;
    private static final Map<String, ASN1ObjectIdentifier> oidMap =
        Collections.unmodifiableMap(new HashMap<String, ASN1ObjectIdentifier>()
        {
            {
                put("nistp256", SECObjectIdentifiers.secp256r1);
                put("nistp384", SECObjectIdentifiers.secp384r1);
                put("nistp521", SECObjectIdentifiers.secp521r1);
                put("nistk163", SECObjectIdentifiers.sect163k1);
                put("nistp192", SECObjectIdentifiers.secp192r1);
                put("nistp224", SECObjectIdentifiers.secp224r1);
                put("nistk233", SECObjectIdentifiers.sect233k1);
                put("nistb233", SECObjectIdentifiers.sect233r1);
                put("nistk283", SECObjectIdentifiers.sect283k1);
                put("nistk409", SECObjectIdentifiers.sect409k1);
                put("nistb409", SECObjectIdentifiers.sect409r1);
                put("nistt571", SECObjectIdentifiers.sect571k1);
            }
        });

    private static final Map<String, String> curveNameToSSHName = Collections.unmodifiableMap(new HashMap<String, String>()
    {
        {
            String[][] curves = {
                {"secp256r1", "nistp256"},
                {"secp384r1", "nistp384"},
                {"secp521r1", "nistp521"},
                {"sect163k1", "nistk163"},
                {"secp192r1", "nistp192"},
                {"secp224r1", "nistp224"},
                {"sect233k1", "nistk233"},
                {"sect233r1", "nistb233"},
                {"sect283k1", "nistk283"},
                {"sect409k1", "nistk409"},
                {"sect409r1", "nistb409"},
                {"sect571k1", "nistt571"}
            };
            for (int i = 0; i != curves.length; i++)
            {
                String[] item = curves[i];
                put(item[0], item[1]);
            }
        }
    });
    private static HashMap<ECCurve, String> curveMap = new HashMap<ECCurve, String>()
    {
        {
            Enumeration<Object> e = CustomNamedCurves.getNames();
            while (e.hasMoreElements())
            {
                String name = (String)e.nextElement();
                X9ECParameters parameters = CustomNamedCurves.getByName(name);
                put(parameters.getCurve(), name);
            }

        }
    };

    static
    {
        oidToName = Collections.unmodifiableMap(new HashMap<ASN1ObjectIdentifier, String>()
        {
            {
                for (Iterator it = oidMap.keySet().iterator(); it.hasNext();)
                {
                    String key = (String)it.next();
                    put(oidMap.get(key), key);
                }
            }
        });


    }

    public static ASN1ObjectIdentifier getByName(String sshName)
    {
        return (ASN1ObjectIdentifier)oidMap.get(sshName);
    }

    public static X9ECParameters getParameters(String sshName)
    {
        return NISTNamedCurves.getByOID((ASN1ObjectIdentifier)oidMap.get(Strings.toLowerCase(sshName)));
    }

    public static X9ECParameters getParameters(ASN1ObjectIdentifier oid)
    {
        return NISTNamedCurves.getByOID(oid);
    }

    public static String getName(ASN1ObjectIdentifier oid)
    {
        return (String)oidToName.get(oid);
    }

    public static String getNameForParameters(ECDomainParameters parameters)
    {
        if (parameters instanceof ECNamedDomainParameters)
        {
            return getName(((ECNamedDomainParameters)parameters).getName());
        }


        return getNameForParameters(parameters.getCurve());
    }

    public static String getNameForParameters(ECCurve curve)
    {
        return (String)curveNameToSSHName.get(curveMap.get(curve));
    }
}
