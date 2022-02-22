package org.bouncycastle.oer.its.ieee1609dot2.basetypes;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;

/**
 * TwoDLocation ::= SEQUENCE {
 * latitude   Latitude,
 * longitude  Longitude
 * }
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

    private TwoDLocation(ASN1Sequence seq)
    {
        if (seq.size() != 2)
        {
            throw new IllegalArgumentException("expected sequence size of 2");
        }
        latitude = Latitude.getInstance(seq.getObjectAt(0));
        longitude = Longitude.getInstance(seq.getObjectAt(1));
    }

    public static TwoDLocation getInstance(Object o)
    {
        if (o instanceof TwoDLocation)
        {
            return (TwoDLocation)o;
        }

        if (o != null)
        {
            return new TwoDLocation(ASN1Sequence.getInstance(o));
        }

        return null;
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


    public static Builder builder()
    {
        return new Builder();
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
