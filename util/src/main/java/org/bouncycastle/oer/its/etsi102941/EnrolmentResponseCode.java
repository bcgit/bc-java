package org.bouncycastle.oer.its.etsi102941;

import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1Enumerated;

public class EnrolmentResponseCode
    extends ASN1Enumerated
{
    private static final EnrolmentResponseCode ok = new EnrolmentResponseCode(0);
    private static final EnrolmentResponseCode cantparse = new EnrolmentResponseCode(1);
    private static final EnrolmentResponseCode badcontenttype = new EnrolmentResponseCode(2);
    private static final EnrolmentResponseCode imnottherecipient = new EnrolmentResponseCode(3);
    private static final EnrolmentResponseCode unknownencryptionalgorithm = new EnrolmentResponseCode(4);
    private static final EnrolmentResponseCode decryptionfailed = new EnrolmentResponseCode(5);
    private static final EnrolmentResponseCode unknownits = new EnrolmentResponseCode(6);
    private static final EnrolmentResponseCode invalidsignature = new EnrolmentResponseCode(7);
    private static final EnrolmentResponseCode invalidencryptionkey = new EnrolmentResponseCode(8);
    private static final EnrolmentResponseCode baditsstatus = new EnrolmentResponseCode(9);
    private static final EnrolmentResponseCode incompleterequest = new EnrolmentResponseCode(10);
    private static final EnrolmentResponseCode deniedpermissions = new EnrolmentResponseCode(11);
    private static final EnrolmentResponseCode invalidkeys = new EnrolmentResponseCode(12);
    private static final EnrolmentResponseCode deniedrequest = new EnrolmentResponseCode(13);

    public EnrolmentResponseCode(int value)
    {
        super(value);
    }

    public EnrolmentResponseCode(BigInteger value)
    {
        super(value);
    }

    public EnrolmentResponseCode(byte[] contents)
    {
        super(contents);
    }

    public static EnrolmentResponseCode getInstance(Object o)
    {
        if (o instanceof EnrolmentResponseCode)
        {
            return (EnrolmentResponseCode)o;
        }
        if (o != null)
        {
            return new EnrolmentResponseCode(ASN1Enumerated.getInstance(o).getValue());
        }
        return null;
    }

}
