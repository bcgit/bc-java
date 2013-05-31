package org.bouncycastle.asn1.test;

import org.bouncycastle.asn1.ASN1UTCTime;
import org.bouncycastle.asn1.DERUTCTime;
import org.bouncycastle.util.test.SimpleTest;

/**
 * X.690 test example
 */
public class UTCTimeTest
    extends SimpleTest
{
    String[] input =
        {
            "020122122220Z",
            "020122122220-1000",
            "020122122220+1000",
            "020122122220+00",
            "0201221222Z",
            "0201221222-1000",
            "0201221222+1000",
            "0201221222+00",
            "550122122220Z",
            "5501221222Z"
        };

    String[] output = {
            "20020122122220GMT+00:00",
            "20020122122220GMT-10:00",
            "20020122122220GMT+10:00",
            "20020122122220GMT+00:00",
            "20020122122200GMT+00:00",
            "20020122122200GMT-10:00",
            "20020122122200GMT+10:00",
            "20020122122200GMT+00:00",
            "19550122122220GMT+00:00",
            "19550122122200GMT+00:00"
             };

    String[] zOutput1 = {
            "20020122122220Z",
            "20020122222220Z",
            "20020122022220Z",
            "20020122122220Z",
            "20020122122200Z",
            "20020122222200Z",
            "20020122022200Z",
            "20020122122200Z",
            "19550122122220Z",
            "19550122122200Z"
    };

    String[] zOutput2 = {
            "20020122122220Z",
            "20020122222220Z",
            "20020122022220Z",
            "20020122122220Z",
            "20020122122200Z",
            "20020122222200Z",
            "20020122022200Z",
            "20020122122200Z",
            "19550122122220Z",
            "19550122122200Z"
    };

    public String getName()
    {
        return "UTCTime";
    }

    public void performTest()
        throws Exception
    {

        for (int i = 0; i != input.length; i++)
        {
            DERUTCTime t = new DERUTCTime(input[i]);

            if (!t.getAdjustedTime().equals(output[i]))
            {
                fail("failed conversion test " + i);
            }

            t = new ASN1UTCTime(zOutput1[i].substring(2));

            if (!new ASN1UTCTime(t.getAdjustedDate()).getAdjustedTime().equals(t.getAdjustedTime()))
            {
                fail("failed equality test");
            }
        }
    }

    public static void main(
        String[]    args)
    {
        runTest(new UTCTimeTest());
    }
}
