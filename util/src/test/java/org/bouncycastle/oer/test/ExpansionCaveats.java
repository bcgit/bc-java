package org.bouncycastle.oer.test;

import java.lang.reflect.Method;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.oer.Element;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.PolygonalRegion;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.TwoDLocation;

public class ExpansionCaveats
{

    public static Class getSequenceOfReturnType(String name) {
        if (name.equals("OctetString")) {
            return ASN1OctetString.class;
        } else if (name.equals("PolygonalRegion")) {
            return TwoDLocation.class;
        }

        return null;
    }

    public static Method getSequenceOfGetterMethod(String name) throws Exception {

        if (name.equals("PolygonalRegion")) {
            return PolygonalRegion.class.getMethod("getTwoDLocations");
        }

        return null;
    }

    public static boolean skip(Element def)
    {

        if ("Ieee1609Dot2HeaderInfoContributedExtensions".equals(def.getLabel())) {
            //
            // This is a base type definition only.
            //
            return true;
        }

        return false;
    }
}
