package org.bouncycastle.crypto.test;

import org.bouncycastle.crypto.digests.Kangaroo.KangarooParameters;
import org.bouncycastle.crypto.digests.Kangaroo.KangarooTwelve;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

/**
 * Test Cases for Kangaroo12. No TestVectors are available for MarsupilamiFourteen.
 * Test Vectors taken from https://tools.ietf.org/html/draft-viguier-kangarootwelve-04.
 */
public class KangarooTest
    extends SimpleTest
{
    /**
     * Kangaroo Data.
     */
    private static final byte[] KANGAROODATA = new byte[256];

    static
    {
        for (int i=0; i < KANGAROODATA.length; i++)
        {
            KANGAROODATA[i] = (byte) i;
        }
    }

    public String getName()
    {
        return "Kangaroo12";
    }

    public void performTest()
        throws Exception
    {
        new Kangaroo12Test().checkDigests(this);
    }

    /**
     * Run the kangaroo tests.
     * @param pMsgLen the messageLength
     * @param pStdMsg is this a  standard message
     * @param pPersLen the personalLength
     * @param pResult the expected result
     */
    void testKangaroo(final int pMsgLen,
                      final boolean pStdMsg,
                      final int pPersLen,
                      final String pResult)
    {
        testKangaroo(pMsgLen, pStdMsg, pPersLen, 0, pResult);
    }

    /**
     * Run the kangaroo tests.
     * @param pMsgLen the messageLength
     * @param pStdMsg is this a  standard message
     * @param pPersLen the personalLength
     * @param pOutLen the outputLength
     * @param pResult the expected result
     */
    void testKangaroo(final int pMsgLen,
                      final boolean pStdMsg,
                      final int pPersLen,
                      final int pOutLen,
                      final String pResult)
    {
        /* Access the expected result */
        final byte[] myExpected = Hex.decode(pResult);
        final int myXofLen = pOutLen == 0 ? myExpected.length : pOutLen;

        /* Create the message */
        final byte[] myMsg = new byte[pMsgLen];
        if (pStdMsg)
        {
            buildStdBuffer(myMsg);
        }
        else
        {
            Arrays.fill(myMsg, (byte) 0xFF);
        }

        /* Create the personalisation */
        final byte[] myPers = pPersLen > 0 ? new byte[pPersLen] : null;
        if (pPersLen > 0)
        {
            buildStdBuffer(myPers);
        }

        /* Create the output buffer */
        byte[] myOutput = new byte[myXofLen];

        /* Initialise the mac */
        final KangarooTwelve myDigest = new KangarooTwelve();
        final KangarooParameters myParams = new KangarooParameters.Builder()
                .setPersonalisation(myPers)
                .setMaxOutputLen(myXofLen)
                .build();
        myDigest.init(myParams);
        myDigest.update(myMsg, 0, pMsgLen);
        myDigest.doFinal(myOutput, 0);

        /* If we are only looking at the last bit of the output */
        if (pOutLen != 0)
        {
            myOutput = Arrays.copyOfRange(myOutput, pOutLen - myExpected.length, pOutLen);
        }

        /* Check the result */
        isTrue("Result mismatch", Arrays.areEqual(myExpected, myOutput));
    }

    /**
     * Build a standard buffer.
     * @param pBuffer the buffer to build
     */
    private static void buildStdBuffer(final byte[] pBuffer)
    {
        for (int i = 0; i < pBuffer.length; i += 251)
        {
            final int myLen = Math.min(251, pBuffer.length - i);
            System.arraycopy(KANGAROODATA, 0, pBuffer, i, myLen);
        }
    }

    /**
     * Kangaroo12Test.
     */
    static class Kangaroo12Test
    {
        /**
         * Expected results.
         */
         private static final String[] EXPECTED =
         {
                 "1AC2D450FC3B4205D19DA7BFCA1B37513C0803577AC7167F06FE2CE1F0EF39E5",
                 "1AC2D450FC3B4205D19DA7BFCA1B37513C0803577AC7167F06FE2CE1F0EF39E54269C056B8C82E48276038B6D292966CC07A3D4645272E31FF38508139EB0A71",
                 "E8DC563642F7228C84684C898405D3A834799158C079B12880277A1D28E2FF6D",
                 "2BDA92450E8B147F8A7CB629E784A058EFCA7CF7D8218E02D345DFAA65244A1F",
                 "6BF75FA2239198DB4772E36478F8E19B0F371205F6A9A93A273F51DF37122888",
                 "0C315EBCDEDBF61426DE7DCF8FB725D1E74675D7F5327A5067F367B108ECB67C",
                 "CB552E2EC77D9910701D578B457DDF772C12E322E4EE7FE417F92C758F0D59D0",
                 "8701045E22205345FF4DDA05555CBB5C3AF1A771C2B89BAEF37DB43D9998B9FE",
                 "844D610933B1B9963CBDEB5AE3B6B05CC7CBD67CEEDF883EB678A0A8E0371682",
                 "3C390782A8A4E89FA6367F72FEAAF13255C8D95878481D3CD8CE85F58E880AF8",
                 "FAB658DB63E94A246188BF7AF69A133045F46EE984C56E3C3328CAAF1AA1A583",
                 "D848C5068CED736F4462159B9867FD4C20B808ACC3D5BC48E0B06BA0A3762EC4",
                 "C389E5009AE57120854C2E8C64670AC01358CF4C1BAF89447A724234DC7CED74",
                 "75D2F86A2E644566726B4FBCFC5657B9DBCF070C7B0DCA06450AB291D7443BCF"
         };

         /**
          * Test digests.
          * @param pTest the test
          */
         void checkDigests(final KangarooTest pTest)
         {
             pTest.testKangaroo(0, true, 0, EXPECTED[0]);
             pTest.testKangaroo(0, true, 0, EXPECTED[1]);
             pTest.testKangaroo(0, true, 0, 10032, EXPECTED[2]);
             pTest.testKangaroo(1, true, 0, EXPECTED[3]);
             pTest.testKangaroo(17, true, 0, EXPECTED[4]);
             pTest.testKangaroo(17*17, true, 0, EXPECTED[5]);
             pTest.testKangaroo(17*17*17, true, 0, EXPECTED[6]);
             pTest.testKangaroo(17*17*17*17, true, 0, EXPECTED[7]);
             pTest.testKangaroo(17*17*17*17*17, true, 0, EXPECTED[8]);
             pTest.testKangaroo(17*17*17*17*17*17, true, 0, EXPECTED[9]);
             pTest.testKangaroo(0, true, 1, EXPECTED[10]);
             pTest.testKangaroo(1, false, 41, EXPECTED[11]);
             pTest.testKangaroo(3, false, 41*41, EXPECTED[12]);
             pTest.testKangaroo(7, false, 41*41*41, EXPECTED[13]);
         }
     }

    /**
     * Main entry point.
     *
     * @param args the argyments
     */
    public static void main(String[] args)
    {
        runTest(new KangarooTest());
    }
}
