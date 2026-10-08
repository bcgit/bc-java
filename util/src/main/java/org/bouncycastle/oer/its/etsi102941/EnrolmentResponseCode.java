package org.bouncycastle.oer.its.etsi102941;

import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1Enumerated;

public class EnrolmentResponseCode
    extends ASN1Enumerated
{
    public static final EnrolmentResponseCode ok = new EnrolmentResponseCode(0);
    public static final EnrolmentResponseCode cantparse = new EnrolmentResponseCode(1);
    public static final EnrolmentResponseCode badcontenttype = new EnrolmentResponseCode(2);
    public static final EnrolmentResponseCode imnottherecipient = new EnrolmentResponseCode(3);
    public static final EnrolmentResponseCode unknownencryptionalgorithm = new EnrolmentResponseCode(4);
    public static final EnrolmentResponseCode decryptionfailed = new EnrolmentResponseCode(5);
    public static final EnrolmentResponseCode unknownits = new EnrolmentResponseCode(6);
    public static final EnrolmentResponseCode invalidsignature = new EnrolmentResponseCode(7);
    public static final EnrolmentResponseCode invalidencryptionkey = new EnrolmentResponseCode(8);
    public static final EnrolmentResponseCode baditsstatus = new EnrolmentResponseCode(9);
    public static final EnrolmentResponseCode incompleterequest = new EnrolmentResponseCode(10);
    public static final EnrolmentResponseCode deniedpermissions = new EnrolmentResponseCode(11);
    public static final EnrolmentResponseCode invalidkeys = new EnrolmentResponseCode(12);
    public static final EnrolmentResponseCode deniedrequest = new EnrolmentResponseCode(13);

    /**
     * The constants indexed by value, for getInstance to return the shared instance. An entry
     * can be null, should the value set ever become sparse, and the lookup checks for that.
     */
    private static final EnrolmentResponseCode[] VALUES = new EnrolmentResponseCode[14];

    static
    {
        VALUES[0] = ok;
        VALUES[1] = cantparse;
        VALUES[2] = badcontenttype;
        VALUES[3] = imnottherecipient;
        VALUES[4] = unknownencryptionalgorithm;
        VALUES[5] = decryptionfailed;
        VALUES[6] = unknownits;
        VALUES[7] = invalidsignature;
        VALUES[8] = invalidencryptionkey;
        VALUES[9] = baditsstatus;
        VALUES[10] = incompleterequest;
        VALUES[11] = deniedpermissions;
        VALUES[12] = invalidkeys;
        VALUES[13] = deniedrequest;
    }

    public EnrolmentResponseCode(int value)
    {
        super(value);
        assertValues();
    }

    public EnrolmentResponseCode(BigInteger value)
    {
        super(value);
        assertValues();
    }

    public EnrolmentResponseCode(byte[] contents)
    {
        super(contents);
        assertValues();
    }


    public static EnrolmentResponseCode getInstance(Object o)
    {
        if (o instanceof EnrolmentResponseCode)
        {
            return (EnrolmentResponseCode)o;
        }
        if (o != null)
        {
            return getInstance(ASN1Enumerated.getInstance(o));
        }
        return null;
    }

    private static EnrolmentResponseCode getInstance(ASN1Enumerated value)
    {
        BigInteger v = value.getValue();
        // the value must index the table: non-negative and within the int range before intValue() is
        // trusted, within the table, and held by a constant (the set may one day be sparse)
        if (v.signum() >= 0 && v.bitLength() < 31)
        {
            int index = v.intValue();
            if (index < VALUES.length)
            {
                EnrolmentResponseCode constant = VALUES[index];
                if (constant != null)
                {
                    return constant;
                }
            }
        }
        throw new IllegalArgumentException("invalid enumeration value " + v);
    }

    protected void assertValues()
    {
        BigInteger value = getValue();
        // intValue() truncates, so a value past the int range has to be rejected before it is consulted
        if (value.signum() < 0 || value.bitLength() > 31 || value.intValue() > 13)
        {
            throw new IllegalArgumentException("invalid enumeration value " + value);
        }
    }
}
