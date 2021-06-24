package org.bouncycastle.oer.its;

import org.bouncycastle.asn1.ASN1Encodable;

/**
 * Common interface for ITS curve points.
 */
public interface EccCurvePoint
    extends ASN1Encodable
{
    byte[] getEncodedPoint();
}
