package org.bouncycastle.asn1.test;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.cmc.ExtendedFailInfo;
import org.bouncycastle.util.test.SimpleTest;


public class ExtendedFailInfoTest
    extends SimpleTest
{

    public static void main(String[] args)
    {
        runTest(new ExtendedFailInfoTest());
    }

    public String getName()
    {
        return "ExtendedFailInfo";
    }

    public void performTest()
        throws Exception
    {
        // OID not real
        ExtendedFailInfo extendedFailInfo = new ExtendedFailInfo(
            new ASN1ObjectIdentifier("1.2.3.2"),
            new ASN1Integer(10L));
        byte[] b = extendedFailInfo.getEncoded();
        ExtendedFailInfo extendedFailInfoResult = ExtendedFailInfo.getInstance(b);

        isEquals("failInfoOID", extendedFailInfo.getFailInfoOID(), extendedFailInfoResult.getFailInfoOID());
        isEquals("failInfoValue", extendedFailInfo.getFailInfoValue(), extendedFailInfoResult.getFailInfoValue());

        try
        {
            ExtendedFailInfo.getInstance(new DERSequence(new ASN1Integer(10L)));
            fail("Sequence must be 2 elements.");
        }
        catch (Throwable t)
        {
            isEquals("Wrong exception type",t.getClass(), IllegalArgumentException.class);
        }

    }
}
