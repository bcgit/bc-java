package org.bouncycastle.oer.its.ieee1609dot2;

import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;

/**
 * PduFunctionalType ::= INTEGER (0..255)
 * tlsHandshake          PduFunctionalType ::= 1
 * iso21177ExtendedAuth  PduFunctionalType ::= 2
 */
public class PduFunctionalType
    extends ASN1Object
{
    // must be first, note field order initialisation.
    private static final BigInteger MAX = BigInteger.valueOf(255);

    public static final PduFunctionalType tlsHandshake = new PduFunctionalType(1);
    public static final PduFunctionalType iso21177ExtendedAuth = new PduFunctionalType(2);


    private final BigInteger functionalType;

    public PduFunctionalType(long value)
    {
        this(BigInteger.valueOf(value));
    }

    public PduFunctionalType(BigInteger value)
    {
        this.functionalType = assertValue(value);
    }

    public PduFunctionalType(byte[] bytes)
    {
        this(new BigInteger(bytes));
    }

    private PduFunctionalType(ASN1Integer instance)
    {
        this(instance.getValue());
    }

    public static PduFunctionalType getInstance(Object src)
    {
        if (src instanceof PduFunctionalType)
        {
            return (PduFunctionalType)src;
        }

        if (src != null)
        {
            return new PduFunctionalType(ASN1Integer.getInstance(src));
        }

        return null;
    }

    public BigInteger getFunctionalType()
    {
        return functionalType;
    }

    public ASN1Primitive toASN1Primitive()
    {
        return new ASN1Integer(functionalType);
    }

    private static BigInteger assertValue(BigInteger value)
    {
        if (value.signum() < 0)
        {
            throw new IllegalArgumentException("value less than 0");
        }

        if (value.compareTo(MAX) > 0)
        {
            throw new IllegalArgumentException("value exceeds " + MAX);
        }

        return value;
    }

}
