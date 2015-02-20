package org.bouncycastle.asn1.x9;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

/**
 * class for describing an ECPoint as a DER object.
 */
public class X9ECPoint
    extends ASN1Object
{
    ECPoint p;
    ASN1OctetString encoding;

    public X9ECPoint(
        ECPoint p)
    {
        this(p, false);
    }

    public X9ECPoint(
        ECPoint p,
        boolean compressed)
    {
        this.p = p.normalize();
        this.encoding = new DEROctetString(p.getEncoded(compressed));
    }

    public X9ECPoint(
        ECCurve          c,
        ASN1OctetString  s)
    {
        this.p = c.decodePoint(s.getOctets());
        this.encoding = new DEROctetString(s.getOctets());
    }

    public ASN1OctetString getPointEncoding()
    {
        return encoding;
    }

    public ECPoint getPoint()
    {
        return p;
    }

    public boolean isPointCompressed()
    {
        byte[] octets = encoding.getOctets();
        return octets != null && octets.length > 0 && (octets[0] == 2 || octets[0] == 3);
    }

    /**
     * Produce an object suitable for an ASN1OutputStream.
     * <pre>
     *  ECPoint ::= OCTET STRING
     * </pre>
     * <p>
     * Octet string produced using ECPoint.getEncoded().
     */
    public ASN1Primitive toASN1Primitive()
    {
        return encoding;
    }
}
