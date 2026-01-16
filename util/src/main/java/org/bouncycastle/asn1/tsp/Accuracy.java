package org.bouncycastle.asn1.tsp;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;

public class Accuracy
    extends ASN1Object
{
    protected static final int MIN_MILLIS = 1;
    protected static final int MAX_MILLIS = 999;
    protected static final int MIN_MICROS = 1;
    protected static final int MAX_MICROS = 999;

    public static Accuracy getInstance(Object obj)
    {
        if (obj instanceof Accuracy)
        {
            return (Accuracy)obj;
        }
        if (obj != null)
        {
            return new Accuracy(ASN1Sequence.getInstance(obj));
        }
        return null;
    }

    public static Accuracy getInstance(ASN1TaggedObject taggedObject, boolean declaredExplicit)
    {
        return new Accuracy(ASN1Sequence.getInstance(taggedObject, declaredExplicit));
    }

    public static Accuracy getTagged(ASN1TaggedObject taggedObject, boolean declaredExplicit)
    {
        return new Accuracy(ASN1Sequence.getTagged(taggedObject, declaredExplicit));
    }

    private final ASN1Integer seconds;
    private final ASN1Integer millis;
    private final ASN1Integer micros;

    /** @deprecated Will be removed */
    protected Accuracy()
    {
        seconds = null;
        millis = null;
        micros = null;
    }

    private Accuracy(ASN1Sequence seq)
    {
        int count = seq.size(), pos = 0;
        if (count < 0 || count > 3)
        {
            throw new IllegalArgumentException("Bad sequence size: " + count);
        }

        // seconds INTEGER OPTIONAL
        ASN1Integer seconds = null;
        if (pos < count)
        {
            ASN1Encodable element = seq.getObjectAt(pos);
            if (element instanceof ASN1Integer)
            {
                pos++;
                seconds = (ASN1Integer)element;
            }
        }
        this.seconds = seconds;

        // millis [0] INTEGER (1..999) OPTIONAL
        ASN1Integer millis = null;
        if (pos < count)
        {
            ASN1TaggedObject tag0 = ASN1TaggedObject.getContextOptional(seq.getObjectAt(pos), 0);
            if (tag0 != null)
            {
                pos++;
                millis = ASN1Integer.getInstance(tag0, false);
            }
        }
        this.millis = millis;

        // micros [1] INTEGER (1..999) OPTIONAL
        ASN1Integer micros = null;
        if (pos < count)
        {
            ASN1TaggedObject tag1 = ASN1TaggedObject.getContextOptional(seq.getObjectAt(pos), 1);
            if (tag1 != null)
            {
                pos++;
                micros = ASN1Integer.getInstance(tag1, false);
            }
        }
        this.micros = micros;

        if (pos != count)
        {
            throw new IllegalArgumentException("Unexpected elements in sequence");
        }

        validate();
    }

    public Accuracy(ASN1Integer seconds, ASN1Integer millis, ASN1Integer micros)
    {
        this.seconds = seconds;
        this.millis = millis;
        this.micros = micros;

        validate();
    }

    public ASN1Integer getSeconds()
    {
        return seconds;
    }

    public ASN1Integer getMillis()
    {
        return millis;
    }

    public ASN1Integer getMicros()
    {
        return micros;
    }

    /**
     * <pre>
     * Accuracy ::= SEQUENCE {
     *             seconds        INTEGER              OPTIONAL,
     *             millis     [0] INTEGER  (1..999)    OPTIONAL,
     *             micros     [1] INTEGER  (1..999)    OPTIONAL
     *             }
     * </pre>
     */
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector(3);

        if (seconds != null)
        {
            v.add(seconds);
        }

        if (millis != null)
        {
            v.add(new DERTaggedObject(false, 0, millis));
        }

        if (micros != null)
        {
            v.add(new DERTaggedObject(false, 1, micros));
        }

        return new DERSequence(v);
    }

    private void validate()
    {
        if (millis != null)
        {
            int millisValue = millis.intValueExact();
            if (millisValue < MIN_MILLIS || millisValue > MAX_MILLIS)
            {
                throw new IllegalArgumentException("Invalid millis field : not in (1..999)");
            }
        }
        if (micros != null)
        {
            int microsValue = micros.intValueExact();
            if (microsValue < MIN_MICROS || microsValue > MAX_MICROS)
            {
                throw new IllegalArgumentException("Invalid micros field : not in (1..999)");
            }
        }
    }
}
