package org.bouncycastle.its.asn1;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;

/**
 * <pre>
 *     Latitude ::= OneEightyDegreeInt
 *
 *     NinetyDegreeInt ::= INTEGER {
 *         min (-17999999999),
 *         max (1800000000),
 *         unknown (1800000001)
 *     }
 * </pre>
 */
public class Longitude
    extends ASN1Object
{
    public ASN1Primitive toASN1Primitive()
    {
        return null;
    }
}
