package org.bouncycastle.oer.its.ieee1609dot2.basetypes;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;

/**
 * <pre>
 *     ThreeDLocation ::= SEQUENCE {
 *        latitude   Latitude,
 *        longitude  Longitude,
 *        elevation  Elevation
 *   }
 * </pre>
 */
public class ThreeDLocation
    extends ASN1Object
{
    private final Latitude latitude;
    private final Longitude longitude;
    private final Elevation elevation;

    public ThreeDLocation(Latitude latitude, Longitude longitude, Elevation elevation)
    {
        this.latitude = latitude;
        this.longitude = longitude;
        this.elevation = elevation;
    }

    private ThreeDLocation(ASN1Sequence sequence)
    {
        if (sequence.size() != 3)
        {
            throw new IllegalArgumentException("expected sequence size of 3");
        }
        latitude = Latitude.getInstance(sequence.getObjectAt(0));
        longitude = Longitude.getInstance(sequence.getObjectAt(1));
        elevation = Elevation.getInstance(sequence.getObjectAt(2));
    }

    public static ThreeDLocation getInstance(Object o)
    {
        if (o instanceof ThreeDLocation)
        {
            return (ThreeDLocation)o;
        }

        if (o != null)
        {
            return new ThreeDLocation(ASN1Sequence.getInstance(o));
        }

        return null;


    }

    public static Builder builder()
    {
        return new Builder();
    }

    public ASN1Primitive toASN1Primitive()
    {
        return new DERSequence(new ASN1Encodable[]{latitude, longitude, elevation});
    }

    public Latitude getLatitude()
    {
        return latitude;
    }

    public Longitude getLongitude()
    {
        return longitude;
    }

    public Elevation getElevation()
    {
        return elevation;
    }

    public static class Builder
    {

        private Latitude latitude;
        private Longitude longitude;
        private Elevation elevation;

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

        public Builder setElevation(Elevation elevation)
        {
            this.elevation = elevation;
            return this;
        }

        public ThreeDLocation createThreeDLocation()
        {
            return new ThreeDLocation(latitude, longitude, elevation);
        }
    }
}
