package org.bouncycastle.asn1.test;

import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.cmp.PollReqContent;
import org.bouncycastle.util.test.SimpleTest;

public class PollReqContentTest
    extends SimpleTest
{
    public String getName()
    {
        return "PollReqContentTest";
    }

    public void performTest()
        throws Exception
    {
        BigInteger one = BigInteger.valueOf(1), two = BigInteger.valueOf(2);
        BigInteger[] ids = new BigInteger[] { one, two };

        PollReqContent c = new PollReqContent(ids);

        ASN1Integer[][] vs = c.getCertReqIds();

        isTrue(vs.length == 2);
        for (int i = 0; i != vs.length; i++)
        {
            isTrue(vs[i].length == 1);
            isTrue(vs[i][0].getValue().equals(ids[i]));
        }

        BigInteger[] values = c.getCertReqIdValues();

        isTrue(values.length == 2);
        for (int i = 0; i != values.length; i++)
        {
            isTrue(values[i].equals(ids[i]));
        }

        c = new PollReqContent(two);
        vs = c.getCertReqIds();

        isTrue(vs.length == 1);

        isTrue(vs[0].length == 1);
        isTrue(vs[0][0].getValue().equals(two));
    }

    public static void main(String[] args)
    {
        runTest(new PollReqContentTest());
    }
}
