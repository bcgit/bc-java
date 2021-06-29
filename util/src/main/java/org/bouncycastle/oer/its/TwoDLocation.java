package org.bouncycastle.oer.its;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;

/**
 * <pre>
 *     TwoDLocation ::= SEQUENCE {
 *         latitude Latitude,
 *         longitude Longitude
 *     }
 * </pre>
 */
public class TwoDLocation
    extends ASN1Object
{
    private final Latitude latitude;
    private final Longitude longitude;

    public TwoDLocation(Latitude latitude, Longitude longitude)
    {
        this.latitude = latitude;
        this.longitude = longitude;
    }

    public static TwoDLocation getInstance(Object o)
    {
        if (o instanceof TwoDLocation)
        {
            return (TwoDLocation)o;
        }

        ASN1Sequence seq = ASN1Sequence.getInstance(o);

        return new TwoDLocation(
            Latitude.getInstance(seq.getObjectAt(0)),
            Longitude.getInstance(seq.getObjectAt(1)));
    }

    public ASN1Primitive toASN1Primitive()
    {
        return new DERSequence(new ASN1Encodable[]{latitude, longitude});
    }

    public Latitude getLatitude()
    {
        return latitude;
    }

    public Longitude getLongitude()
    {
        return longitude;
    }

    public static class Builder
    {

        private Latitude latitude;
        private Longitude longitude;

        public Builder setLatitude(Latitude latitude)
        {
            this.latitude = latitude;
            return this;
        }

        public Builder setLongitude(Longitude longitude)
        {
            this.longitude = longitude;
            return this;
        }

        public TwoDLocation createTwoDLocation()
        {
            return new TwoDLocation(latitude, longitude);
        }
    }
}
