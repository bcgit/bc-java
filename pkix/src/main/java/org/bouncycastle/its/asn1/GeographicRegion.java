package org.bouncycastle.its.asn1;

import org.bouncycastle.asn1.ASN1Choice;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;

/**
 * <pre>
 *     GeographicRegion ::= CHOICE {
 *         circularRegion CircularRegion,
 *         rectangularRegion SequenceOfRectangularRegion,
 *         polygonalRegion PolygonalRegion,
 *         identifiedRegion SequenceOfIdentifiedRegion,
 *         ...
 *     }
 * </pre>
 */
public class GeographicRegion
    extends ASN1Object
    implements ASN1Choice
{
    public ASN1Primitive toASN1Primitive()
    {
        return null;
    }
}
