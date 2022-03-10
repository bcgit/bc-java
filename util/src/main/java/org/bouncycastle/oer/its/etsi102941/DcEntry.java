package org.bouncycastle.oer.its.etsi102941;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.SequenceOfHashedId8;


/**
 * DcEntry ::= SEQUENCE {
 * url  Url,
 * cert  SEQUENCE OF HashedId8
 * }
 */
public class DcEntry
    extends ASN1Object
{
    private final Url url;
    private final SequenceOfHashedId8 cert;

    public DcEntry(Url url, SequenceOfHashedId8 cert)
    {
        this.url = url;
        this.cert = cert;
    }


    private DcEntry(ASN1Sequence sequence)
    {
        if (sequence.size() != 2)
        {
            throw new IllegalArgumentException("expected sequence size of 2");
        }
        this.url = Url.getInstance(sequence.getObjectAt(0));
        this.cert = SequenceOfHashedId8.getInstance(sequence.getObjectAt(1));
    }

    public static DcEntry getInstance(Object o)
    {
        if (o instanceof DcEntry)
        {
            return (DcEntry)o;
        }
        if (o != null)
        {
            return new DcEntry(ASN1Sequence.getInstance(o));
        }
        return null;
    }


    public Url getUrl()
    {
        return url;
    }

    public SequenceOfHashedId8 getCert()
    {
        return cert;
    }

    public ASN1Primitive toASN1Primitive()
    {
        return new DERSequence(new ASN1Encodable[]{url, cert});
    }

    public static Builder builder()
    {
        return new Builder();
    }

    public static class Builder
    {
        private Url url;
        private SequenceOfHashedId8 cert;

        public Builder setUrl(Url url)
        {
            this.url = url;
            return this;
        }

        public Builder setCert(SequenceOfHashedId8 cert)
        {
            this.cert = cert;
            return this;
        }

        public DcEntry createDcEntry()
        {
            return new DcEntry(url, cert);
        }
    }

}
