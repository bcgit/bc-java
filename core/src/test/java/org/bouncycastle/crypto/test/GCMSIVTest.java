package org.bouncycastle.crypto.test;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.modes.GCMSIVBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

/**
 * AES-GCM_SIV test cases.
 */
public class GCMSIVTest
        extends SimpleTest
{
    public String getName()
    {
        return "GCM-SIV";
    }

    public void performTest()
            throws Exception
    {
        new AESGCMSIV128Test1().testTheCipher(this);
        new AESGCMSIV128Test2().testTheCipher(this);
        new AESGCMSIV128Test3().testTheCipher(this);
        new AESGCMSIV256Test1().testTheCipher(this);
        new AESGCMSIV256Test2().testTheCipher(this);
        new AESGCMSIV256Test3().testTheCipher(this);
        new AESGCMSIV256Test4().testTheCipher(this);
    }

    /**
     * Test the GCMSIVCipher against the results.
     * @param pCipher the cipher to test.
     * @param pKey the key to test
     * @param pNonce the nonce
     * @param pAEAD the AEAD
     * @param pData the data to test
     * @param pExpected the expected results
     */
    void testSIVCipher(final GCMSIVBlockCipher pCipher,
                       final String pKey,
                       final String pNonce,
                       final String pAEAD,
                       final String pData,
                       final String pExpected)
    {
        /* protect against exceptions */
        try
        {
            /* Access the key and the data */
            final KeyParameter myKey = new KeyParameter(Hex.decode(pKey));
            final byte[] myNonce = Hex.decode(pNonce);
            final byte[] myAEAD = Hex.decode(pAEAD);
            final byte[] myData = Hex.decode(pData);

            /* Initialise the cipher */
            final AEADParameters myParams = new AEADParameters(myKey, 128, myNonce, myAEAD);
            pCipher.init(true, myParams);

            /* Create the output buffers */
            final byte[] myOutput = new byte[pCipher.getOutputSize(myData.length)];
            final byte[] myFinal = new byte[myData.length];

            /* Process the data */
            pCipher.processBytes(myData, 0, myData.length, null, 0);
            pCipher.doFinal(myOutput, 0);

            /* Check the encryption */
            final byte[] myExpected = Hex.decode(pExpected);
            isTrue("Encryption mismatch", Arrays.areEqual(myExpected, myOutput));

            /* Repeat processing byte at a time */
            for (int i = 0; i != myData.length; i++)
            {
                pCipher.processByte(myData[i], null, 0);
            }
            pCipher.doFinal(myOutput, 0);
            isTrue("Encryption mismatch", Arrays.areEqual(myExpected, myOutput));

            if (myData.length >= 2)
            {
                /* Repeat processing checking processBytes with non-empty internal buffer */
                pCipher.processByte(myData[0], null, 0);
                pCipher.processBytes(myData, 1, myData.length - 1, null, 0);
                pCipher.doFinal(myOutput, 0);
                isTrue("Encryption mismatch", Arrays.areEqual(myExpected, myOutput));
            }

            /* Re-initialise the cipher */
            pCipher.init(false, myParams);
            pCipher.processBytes(myOutput, 0, myOutput.length, null, 0);
            pCipher.doFinal(myFinal, 0);
            isTrue("Decryption mismatch", Arrays.areEqual(myData, myFinal));
        }
        catch (InvalidCipherTextException e)
        {
            fail("Bad Text", e);
        }
    }

    /**
     * AES-GCM-SIV-128 Set 1.
     */
    static class AESGCMSIV128Test1
    {
        private static final String EMPTY       = "";
        private static final String KEY_1       = "01000000000000000000000000000000";
        private static final String NONCE_1     = "030000000000000000000000";
        private static final String DATA_8      = "0100000000000000";
        private static final String DATA_12     = "010000000000000000000000";
        private static final String DATA_16     = "01000000000000000000000000000000";
        private static final String DATA_32     = "01000000000000000000000000000000" + "02000000000000000000000000000000";
        private static final String DATA_48     = "01000000000000000000000000000000" + "02000000000000000000000000000000"
                + "03000000000000000000000000000000";
        private static final String DATA_64     = "01000000000000000000000000000000" + "02000000000000000000000000000000"
                + "03000000000000000000000000000000" + "04000000000000000000000000000000";
        private static final String EXPECTED_1  = "dc20e2d83f25705bb49e439eca56de25";
        private static final String EXPECTED_2  = "b5d839330ac7b786578782fff6013b81" + "5b287c22493a364c";
        private static final String EXPECTED_3  = "7323ea61d05932260047d942a4978db3" + "57391a0bc4fdec8b0d106639";
        private static final String EXPECTED_4  = "743f7c8077ab25f8624e2e948579cf77" + "303aaf90f6fe21199c6068577437a0c4";
        private static final String EXPECTED_5  = "84e07e62ba83a6585417245d7ec413a9" + "fe427d6315c09b57ce45f2e3936a9445"
                + "1a8e45dcd4578c667cd86847bf6155ff";
        private static final String EXPECTED_6  = "3fd24ce1f5a67b75bf2351f181a475c7" + "b800a5b4d3dcf70106b1eea82fa1d64d"
                + "f42bf7226122fa92e17a40eeaac1201b" + "5e6e311dbf395d35b0fe39c2714388f8";
        private static final String EXPECTED_7  = "2433668f1058190f6d43e360f4f35cd8" + "e475127cfca7028ea8ab5c20f7ab2af0"
                + "2516a2bdcbc08d521be37ff28c152bba" + "36697f25b4cd169c6590d1dd39566d3f"
                + "8a263dd317aa88d56bdf3936dba75bb8";

        /**
         * Test cipher.
         * @param pTest the test engine
         */
        void testTheCipher(final GCMSIVTest pTest)
        {
            pTest.testSIVCipher(new GCMSIVBlockCipher(), KEY_1, NONCE_1, EMPTY, EMPTY, EXPECTED_1);
            pTest.testSIVCipher(new GCMSIVBlockCipher(), KEY_1, NONCE_1, EMPTY, DATA_8, EXPECTED_2);
            pTest.testSIVCipher(new GCMSIVBlockCipher(), KEY_1, NONCE_1, EMPTY, DATA_12, EXPECTED_3);
            pTest.testSIVCipher(new GCMSIVBlockCipher(), KEY_1, NONCE_1, EMPTY, DATA_16, EXPECTED_4);
            pTest.testSIVCipher(new GCMSIVBlockCipher(), KEY_1, NONCE_1, EMPTY, DATA_32, EXPECTED_5);
            pTest.testSIVCipher(new GCMSIVBlockCipher(), KEY_1, NONCE_1, EMPTY, DATA_48, EXPECTED_6);
            pTest.testSIVCipher(new GCMSIVBlockCipher(), KEY_1, NONCE_1, EMPTY, DATA_64, EXPECTED_7);
        }
    }

    /**
     * AES-GCM-SIV-128 Set 2.
     */
    static class AESGCMSIV128Test2
    {
        private static final String KEY_1       = "01000000000000000000000000000000";
        private static final String NONCE_1     = "030000000000000000000000";
        private static final String AEAD_1      = "01";
        private static final String AEAD_12     = "010000000000000000000000";
        private static final String AEAD_18     = "01000000000000000000000000000000" + "0200";
        private static final String AEAD_20     = "01000000000000000000000000000000" + "02000000";
        private static final String DATA_4      = "02000000";
        private static final String DATA_8      = "0200000000000000";
        private static final String DATA_12     = "020000000000000000000000";
        private static final String DATA_16     = "02000000000000000000000000000000";
        private static final String DATA_18     = "03000000000000000000000000000000" + "0400";
        private static final String DATA_20     = "03000000000000000000000000000000" + "04000000";
        private static final String DATA_32     = "02000000000000000000000000000000" + "03000000000000000000000000000000";
        private static final String DATA_48     = "02000000000000000000000000000000" + "03000000000000000000000000000000"
                + "04000000000000000000000000000000";
        private static final String DATA_64     = "02000000000000000000000000000000" + "03000000000000000000000000000000"
                + "04000000000000000000000000000000" + "05000000000000000000000000000000";
        private static final String EXPECTED_1  = "1e6daba35669f4273b0a1a2560969cdf" + "790d99759abd1508";
        private static final String EXPECTED_2  = "296c7889fd99f41917f4462008299c51" + "02745aaa3a0c469fad9e075a";
        private static final String EXPECTED_3  = "e2b0c5da79a901c1745f700525cb335b" + "8f8936ec039e4e4bb97ebd8c4457441f";
        private static final String EXPECTED_4  = "620048ef3c1e73e57e02bb8562c416a3" + "19e73e4caac8e96a1ecb2933145a1d71"
                + "e6af6a7f87287da059a71684ed3498e1";
        private static final String EXPECTED_5  = "50c8303ea93925d64090d07bd109dfd9" + "515a5a33431019c17d93465999a8b005"
                + "3201d723120a8562b838cdff25bf9d1e" + "6a8cc3865f76897c2e4b245cf31c51f2";
        private static final String EXPECTED_6  = "2f5c64059db55ee0fb847ed513003746" + "aca4e61c711b5de2e7a77ffd02da42fe"
                + "ec601910d3467bb8b36ebbaebce5fba3" + "0d36c95f48a3e7980f0e7ac299332a80"
                + "cdc46ae475563de037001ef84ae21744";
        private static final String EXPECTED_7  = "a8fe3e8707eb1f84fb28f8cb73de8e99" + "e2f48a14";
        private static final String EXPECTED_8  = "6bb0fecf5ded9b77f902c7d5da236a43" + "91dd029724afc9805e976f451e6d87f6"
                + "fe106514";
        private static final String EXPECTED_9  = "44d0aaf6fb2f1f34add5e8064e83e12a" + "2adabff9b2ef00fb47920cc72a0c0f13"
                + "b9fd";

        /**
         * Test cipher.
         * @param pTest the test engine
         */
        void testTheCipher(final GCMSIVTest pTest)
        {
            pTest.testSIVCipher(new GCMSIVBlockCipher(), KEY_1, NONCE_1, AEAD_1, DATA_8, EXPECTED_1);
            pTest.testSIVCipher(new GCMSIVBlockCipher(), KEY_1, NONCE_1, AEAD_1, DATA_12, EXPECTED_2);
            pTest.testSIVCipher(new GCMSIVBlockCipher(), KEY_1, NONCE_1, AEAD_1, DATA_16, EXPECTED_3);
            pTest.testSIVCipher(new GCMSIVBlockCipher(), KEY_1, NONCE_1, AEAD_1, DATA_32, EXPECTED_4);
            pTest.testSIVCipher(new GCMSIVBlockCipher(), KEY_1, NONCE_1, AEAD_1, DATA_48, EXPECTED_5);
            pTest.testSIVCipher(new GCMSIVBlockCipher(), KEY_1, NONCE_1, AEAD_1, DATA_64, EXPECTED_6);
            pTest.testSIVCipher(new GCMSIVBlockCipher(), KEY_1, NONCE_1, AEAD_12, DATA_4, EXPECTED_7);
            pTest.testSIVCipher(new GCMSIVBlockCipher(), KEY_1, NONCE_1, AEAD_18, DATA_20, EXPECTED_8);
            pTest.testSIVCipher(new GCMSIVBlockCipher(), KEY_1, NONCE_1, AEAD_20, DATA_18, EXPECTED_9);
        }
    }

    /**
     * AES-GCM-SIV-128 Set 3.
     */
    static class AESGCMSIV128Test3
    {
        private static final String EMPTY       = "";
        private static final String KEY_1       = "e66021d5eb8e4f4066d4adb9c33560e4";
        private static final String KEY_2       = "36864200e0eaf5284d884a0e77d31646";
        private static final String KEY_3       = "aedb64a6c590bc84d1a5e269e4b47801";
        private static final String KEY_4       = "d5cc1fd161320b6920ce07787f86743b";
        private static final String KEY_5       = "b3fed1473c528b8426a582995929a149";
        private static final String KEY_6       = "2d4ed87da44102952ef94b02b805249b";
        private static final String KEY_7       = "bde3b2f204d1e9f8b06bc47f9745b3d1";
        private static final String KEY_8       = "f901cfe8a69615a93fdf7a98cad48179";
        private static final String NONCE_1     = "f46e44bb3da0015c94f70887";
        private static final String NONCE_2     = "bae8e37fc83441b16034566b";
        private static final String NONCE_3     = "afc0577e34699b9e671fdd4f";
        private static final String NONCE_4     = "275d1ab32f6d1f0434d8848c";
        private static final String NONCE_5     = "9e9ad8780c8d63d0ab4149c0";
        private static final String NONCE_6     = "ac80e6f61455bfac8308a2d4";
        private static final String NONCE_7     = "ae06556fb6aa7890bebc18fe";
        private static final String NONCE_8     = "6245709fb18853f68d833640";
        private static final String AEAD_2      = "46bb91c3c5";
        private static final String AEAD_3      = "fc880c94a95198874296";
        private static final String AEAD_4      = "046787f3ea22c127aaf195d1894728";
        private static final String AEAD_5      = "c9882e5386fd9f92ec489c8fde2be2cf" + "97e74e93";
        private static final String AEAD_6      = "2950a70d5a1db2316fd568378da107b5" + "2b0da55210cc1c1b0a";
        private static final String AEAD_7      = "1860f762ebfbd08284e421702de0de18" + "baa9c9596291b08466f37de21c7f";
        private static final String AEAD_8      = "7576f7028ec6eb5ea7e298342a94d4b2" + "02b370ef9768ec6561c4fe6b7e7296fa"
                + "859c21";
        private static final String DATA_2      = "7a806c";
        private static final String DATA_3      = "bdc66f146545";
        private static final String DATA_4      = "1177441f195495860f";
        private static final String DATA_5      = "9f572c614b4745914474e7c7";
        private static final String DATA_6      = "0d8c8451178082355c9e940fea2f58";
        private static final String DATA_7      = "6b3db4da3d57aa94842b9803a96e07fb" + "6de7";
        private static final String DATA_8      = "e42a3c02c25b64869e146d7b233987bd" + "dfc240871d";
        private static final String EXPECTED_1  = "a4194b79071b01a87d65f706e3949578";
        private static final String EXPECTED_2  = "af60eb711bd85bc1e4d3e0a462e074ee" + "a428a8";
        private static final String EXPECTED_3  = "bb93a3e34d3cd6a9c45545cfc11f03ad" + "743dba20f966";
        private static final String EXPECTED_4  = "4f37281f7ad12949d01d02fd0cd174c8" + "4fc5dae2f60f52fd2b";
        private static final String EXPECTED_5  = "f54673c5ddf710c745641c8bc1dc2f87" + "1fb7561da1286e655e24b7b0";
        private static final String EXPECTED_6  = "c9ff545e07b88a015f05b274540aa183" + "b3449b9f39552de99dc214a1190b0b";
        private static final String EXPECTED_7  = "6298b296e24e8cc35dce0bed484b7f30" + "d5803e377094f04709f64d7b985310a4"
                + "db84";
        private static final String EXPECTED_8  = "391cc328d484a4f46406181bcd62efd9" + "b3ee197d052d15506c84a9edd65e13e9"
                + "d24a2a6e70";

        /**
         * Test cipher.
         * @param pTest the test engine
         */
        void testTheCipher(final GCMSIVTest pTest)
        {
            pTest.testSIVCipher(new GCMSIVBlockCipher(), KEY_1, NONCE_1, EMPTY, EMPTY, EXPECTED_1);
            pTest.testSIVCipher(new GCMSIVBlockCipher(), KEY_2, NONCE_2, AEAD_2, DATA_2, EXPECTED_2);
            pTest.testSIVCipher(new GCMSIVBlockCipher(), KEY_3, NONCE_3, AEAD_3, DATA_3, EXPECTED_3);
            pTest.testSIVCipher(new GCMSIVBlockCipher(), KEY_4, NONCE_4, AEAD_4, DATA_4, EXPECTED_4);
            pTest.testSIVCipher(new GCMSIVBlockCipher(), KEY_5, NONCE_5, AEAD_5, DATA_5, EXPECTED_5);
            pTest.testSIVCipher(new GCMSIVBlockCipher(), KEY_6, NONCE_6, AEAD_6, DATA_6, EXPECTED_6);
            pTest.testSIVCipher(new GCMSIVBlockCipher(), KEY_7, NONCE_7, AEAD_7, DATA_7, EXPECTED_7);
            pTest.testSIVCipher(new GCMSIVBlockCipher(), KEY_8, NONCE_8, AEAD_8, DATA_8, EXPECTED_8);
        }
    }

    /**
     * AES-GCM-SIV-256 Set 1.
     */
    static class AESGCMSIV256Test1
    {
        private static final String EMPTY       = "";
        private static final String KEY_1       = "01000000000000000000000000000000" + "00000000000000000000000000000000";
        private static final String NONCE_1     = "030000000000000000000000";
        private static final String DATA_8      = "0100000000000000";
        private static final String DATA_12     = "010000000000000000000000";
        private static final String DATA_16     = "01000000000000000000000000000000";
        private static final String DATA_32     = "01000000000000000000000000000000" + "02000000000000000000000000000000";
        private static final String DATA_48     = "01000000000000000000000000000000" + "02000000000000000000000000000000"
                + "03000000000000000000000000000000";
        private static final String DATA_64     = "01000000000000000000000000000000" + "02000000000000000000000000000000"
                + "03000000000000000000000000000000" + "04000000000000000000000000000000";
        private static final String EXPECTED_1  = "07f5f4169bbf55a8400cd47ea6fd400f";
        private static final String EXPECTED_2  = "c2ef328e5c71c83b843122130f7364b7" + "61e0b97427e3df28";
        private static final String EXPECTED_3  = "9aab2aeb3faa0a34aea8e2b18ca50da9" + "ae6559e48fd10f6e5c9ca17e";
        private static final String EXPECTED_4  = "85a01b63025ba19b7fd3ddfc033b3e76" + "c9eac6fa700942702e90862383c6c366";
        private static final String EXPECTED_5  = "4a6a9db4c8c6549201b9edb53006cba8" + "21ec9cf850948a7c86c68ac7539d027f"
                + "e819e63abcd020b006a976397632eb5d";
        private static final String EXPECTED_6  = "c00d121893a9fa603f48ccc1ca3c57ce" + "7499245ea0046db16c53c7c66fe717e3"
                + "9cf6c748837b61f6ee3adcee17534ed5" + "790bc96880a99ba804bd12c0e6a22cc4";
        private static final String EXPECTED_7  = "c2d5160a1f8683834910acdafc41fbb1" + "632d4a353e8b905ec9a5499ac34f96c7"
                + "e1049eb080883891a4db8caaa1f99dd0" + "04d80487540735234e3744512c6f90ce"
                + "112864c269fc0d9d88c61fa47e39aa08";

        /**
         * Test cipher.
         * @param pTest the test engine
         */
        void testTheCipher(final GCMSIVTest pTest)
        {
            pTest.testSIVCipher(new GCMSIVBlockCipher(), KEY_1, NONCE_1, EMPTY, EMPTY, EXPECTED_1);
            pTest.testSIVCipher(new GCMSIVBlockCipher(), KEY_1, NONCE_1, EMPTY, DATA_8, EXPECTED_2);
            pTest.testSIVCipher(new GCMSIVBlockCipher(), KEY_1, NONCE_1, EMPTY, DATA_12, EXPECTED_3);
            pTest.testSIVCipher(new GCMSIVBlockCipher(), KEY_1, NONCE_1, EMPTY, DATA_16, EXPECTED_4);
            pTest.testSIVCipher(new GCMSIVBlockCipher(), KEY_1, NONCE_1, EMPTY, DATA_32, EXPECTED_5);
            pTest.testSIVCipher(new GCMSIVBlockCipher(), KEY_1, NONCE_1, EMPTY, DATA_48, EXPECTED_6);
            pTest.testSIVCipher(new GCMSIVBlockCipher(), KEY_1, NONCE_1, EMPTY, DATA_64, EXPECTED_7);
        }
    }

    /**
     * AES-GCM-SIV-256 Set 2.
     */
    static class AESGCMSIV256Test2
    {
        private static final String KEY_1       = "01000000000000000000000000000000" + "00000000000000000000000000000000";
        private static final String NONCE_1     = "030000000000000000000000";
        private static final String AEAD_1      = "01";
        private static final String AEAD_12     = "010000000000000000000000";
        private static final String AEAD_18     = "01000000000000000000000000000000" + "0200";
        private static final String AEAD_20     = "01000000000000000000000000000000" + "02000000";
        private static final String DATA_4      = "02000000";
        private static final String DATA_8      = "0200000000000000";
        private static final String DATA_12     = "020000000000000000000000";
        private static final String DATA_16     = "02000000000000000000000000000000";
        private static final String DATA_18     = "03000000000000000000000000000000" + "0400";
        private static final String DATA_20     = "03000000000000000000000000000000" + "04000000";
        private static final String DATA_32     = "02000000000000000000000000000000" + "03000000000000000000000000000000";
        private static final String DATA_48     = "02000000000000000000000000000000" + "03000000000000000000000000000000"
                + "04000000000000000000000000000000";
        private static final String DATA_64     = "02000000000000000000000000000000" + "03000000000000000000000000000000"
                + "04000000000000000000000000000000" + "05000000000000000000000000000000";
        private static final String EXPECTED_1  = "1de22967237a813291213f267e3b452f" + "02d01ae33e4ec854";
        private static final String EXPECTED_2  = "163d6f9cc1b346cd453a2e4cc1a4a19a" + "e800941ccdc57cc8413c277f";
        private static final String EXPECTED_3  = "c91545823cc24f17dbb0e9e807d5ec17" + "b292d28ff61189e8e49f3875ef91aff7";
        private static final String EXPECTED_4  = "07dad364bfc2b9da89116d7bef6daaaf" + "6f255510aa654f920ac81b94e8bad365"
                + "aea1bad12702e1965604374aab96dbbc";
        private static final String EXPECTED_5  = "c67a1f0f567a5198aa1fcc8e3f213143" + "36f7f51ca8b1af61feac35a86416fa47"
                + "fbca3b5f749cdf564527f2314f42fe25" + "03332742b228c647173616cfd44c54eb";
        private static final String EXPECTED_6  = "67fd45e126bfb9a79930c43aad2d3696" + "7d3f0e4d217c1e551f59727870beefc9"
                + "8cb933a8fce9de887b1e40799988db1f" + "c3f91880ed405b2dd298318858467c89"
                + "5bde0285037c5de81e5b570a049b62a0";
        private static final String EXPECTED_7  = "22b3f4cd1835e517741dfddccfa07fa4" + "661b74cf";
        private static final String EXPECTED_8  = "43dd0163cdb48f9fe3212bf61b201976" + "067f342bb879ad976d8242acc188ab59"
                + "cabfe307";
        private static final String EXPECTED_9  = "462401724b5ce6588d5a54aae5375513" + "a075cfcdf5042112aa29685c912fc205"
                + "6543";

        /**
         * Test cipher.
         * @param pTest the test engine
         */
        void testTheCipher(final GCMSIVTest pTest)
        {
            pTest.testSIVCipher(new GCMSIVBlockCipher(), KEY_1, NONCE_1, AEAD_1, DATA_8, EXPECTED_1);
            pTest.testSIVCipher(new GCMSIVBlockCipher(), KEY_1, NONCE_1, AEAD_1, DATA_12, EXPECTED_2);
            pTest.testSIVCipher(new GCMSIVBlockCipher(), KEY_1, NONCE_1, AEAD_1, DATA_16, EXPECTED_3);
            pTest.testSIVCipher(new GCMSIVBlockCipher(), KEY_1, NONCE_1, AEAD_1, DATA_32, EXPECTED_4);
            pTest.testSIVCipher(new GCMSIVBlockCipher(), KEY_1, NONCE_1, AEAD_1, DATA_48, EXPECTED_5);
            pTest.testSIVCipher(new GCMSIVBlockCipher(), KEY_1, NONCE_1, AEAD_1, DATA_64, EXPECTED_6);
            pTest.testSIVCipher(new GCMSIVBlockCipher(), KEY_1, NONCE_1, AEAD_12, DATA_4, EXPECTED_7);
            pTest.testSIVCipher(new GCMSIVBlockCipher(), KEY_1, NONCE_1, AEAD_18, DATA_20, EXPECTED_8);
            pTest.testSIVCipher(new GCMSIVBlockCipher(), KEY_1, NONCE_1, AEAD_20, DATA_18, EXPECTED_9);
        }
    }

    /**
     * AES-GCM-SIV-256 Set 3.
     */
    static class AESGCMSIV256Test3
    {
        private static final String EMPTY       = "";
        private static final String KEY_1       = "e66021d5eb8e4f4066d4adb9c33560e4" + "f46e44bb3da0015c94f7088736864200";
        private static final String KEY_2       = "bae8e37fc83441b16034566b7a806c46" + "bb91c3c5aedb64a6c590bc84d1a5e269";
        private static final String KEY_3       = "6545fc880c94a95198874296d5cc1fd1" + "61320b6920ce07787f86743b275d1ab3";
        private static final String KEY_4       = "d1894728b3fed1473c528b8426a58299" + "5929a1499e9ad8780c8d63d0ab4149c0";
        private static final String KEY_5       = "a44102952ef94b02b805249bac80e6f6" + "1455bfac8308a2d40d8c845117808235";
        private static final String KEY_6       = "9745b3d1ae06556fb6aa7890bebc18fe" + "6b3db4da3d57aa94842b9803a96e07fb";
        private static final String KEY_7       = "b18853f68d833640e42a3c02c25b6486" + "9e146d7b233987bddfc240871d7576f7";
        private static final String KEY_8       = "3c535de192eaed3822a2fbbe2ca9dfc8" + "8255e14a661b8aa82cc54236093bbc23";
        private static final String NONCE_1     = "e0eaf5284d884a0e77d31646";
        private static final String NONCE_2     = "e4b47801afc0577e34699b9e";
        private static final String NONCE_3     = "2f6d1f0434d8848c1177441f";
        private static final String NONCE_4     = "9f572c614b4745914474e7c7";
        private static final String NONCE_5     = "5c9e940fea2f582950a70d5a";
        private static final String NONCE_6     = "6de71860f762ebfbd08284e4";
        private static final String NONCE_7     = "028ec6eb5ea7e298342a94d4";
        private static final String NONCE_8     = "688089e55540db1872504e1c";
        private static final String AEAD_2      = "4fbdc66f14";
        private static final String AEAD_3      = "6787f3ea22c127aaf195";
        private static final String AEAD_4      = "489c8fde2be2cf97e74e932d4ed87d";
        private static final String AEAD_5      = "0da55210cc1c1b0abde3b2f204d1e9f8" + "b06bc47f";
        private static final String AEAD_6      = "f37de21c7ff901cfe8a69615a93fdf7a" + "98cad481796245709f";
        private static final String AEAD_7      = "9c2159058b1f0fe91433a5bdc20e214e" + "ab7fecef4454a10ef0657df21ac7";
        private static final String AEAD_8      = "734320ccc9d9bbbb19cb81b2af4ecbc3" + "e72834321f7aa0f70b7282b4f33df23f"
                + "167541";
        private static final String DATA_2      = "671fdd";
        private static final String DATA_3      = "195495860f04";
        private static final String DATA_4      = "c9882e5386fd9f92ec";
        private static final String DATA_5      = "1db2316fd568378da107b52b";
        private static final String DATA_6      = "21702de0de18baa9c9596291b08466";
        private static final String DATA_7      = "b202b370ef9768ec6561c4fe6b7e7296" + "fa85";
        private static final String DATA_8      = "ced532ce4159b035277d4dfbb7db6296" + "8b13cd4eec";
        private static final String EXPECTED_1  = "169fbb2fbf389a995f6390af22228a62";
        private static final String EXPECTED_2  = "0eaccb93da9bb81333aee0c785b240d3" + "19719d";
        private static final String EXPECTED_3  = "a254dad4f3f96b62b84dc40c84636a5e" + "c12020ec8c2c";
        private static final String EXPECTED_4  = "0df9e308678244c44bc0fd3dc6628dfe" + "55ebb0b9fb2295c8c2";
        private static final String EXPECTED_5  = "8dbeb9f7255bf5769dd56692404099c2" + "587f64979f21826706d497d5";
        private static final String EXPECTED_6  = "793576dfa5c0f88729a7ed3c2f1bffb3" + "080d28f6ebb5d3648ce97bd5ba67fd";
        private static final String EXPECTED_7  = "857e16a64915a787637687db4a951963" + "5cdd454fc2a154fea91f8363a39fec7d"
                + "0a49";
        private static final String EXPECTED_8  = "626660c26ea6612fb17ad91e8e767639" + "edd6c9faee9d6c7029675b89eaf4ba1d"
                + "ed1a286594";

        /**
         * Test cipher.
         * @param pTest the test engine
         */
        void testTheCipher(final GCMSIVTest pTest)
        {
            pTest.testSIVCipher(new GCMSIVBlockCipher(), KEY_1, NONCE_1, EMPTY, EMPTY, EXPECTED_1);
            pTest.testSIVCipher(new GCMSIVBlockCipher(), KEY_2, NONCE_2, AEAD_2, DATA_2, EXPECTED_2);
            pTest.testSIVCipher(new GCMSIVBlockCipher(), KEY_3, NONCE_3, AEAD_3, DATA_3, EXPECTED_3);
            pTest.testSIVCipher(new GCMSIVBlockCipher(), KEY_4, NONCE_4, AEAD_4, DATA_4, EXPECTED_4);
            pTest.testSIVCipher(new GCMSIVBlockCipher(), KEY_5, NONCE_5, AEAD_5, DATA_5, EXPECTED_5);
            pTest.testSIVCipher(new GCMSIVBlockCipher(), KEY_6, NONCE_6, AEAD_6, DATA_6, EXPECTED_6);
            pTest.testSIVCipher(new GCMSIVBlockCipher(), KEY_7, NONCE_7, AEAD_7, DATA_7, EXPECTED_7);
            pTest.testSIVCipher(new GCMSIVBlockCipher(), KEY_8, NONCE_8, AEAD_8, DATA_8, EXPECTED_8);
        }
    }

    /**
     * AES-GCM-SIV-256 Set 4.
     */
    static class AESGCMSIV256Test4
    {
        private static final String EMPTY       = "";
        private static final String KEY_1       = "00000000000000000000000000000000" + "00000000000000000000000000000000";
        private static final String NONCE_1     = "000000000000000000000000";
        private static final String DATA_1      = "00000000000000000000000000000000" + "4db923dc793ee6497c76dcc03a98e108";
        private static final String DATA_2      = "eb3640277c7ffd1303c7a542d02d3e4c" + "0000000000000000";
        private static final String EXPECTED_1  = "f3f80f2cf0cb2dd9c5984fcda908456c" + "c537703b5ba70324a6793a7bf218d3ea"
                + "ffffffff000000000000000000000000";
        private static final String EXPECTED_2  = "18ce4f0b8cb4d0cac65fea8f79257b20" + "888e53e72299e56dffffffff00000000"
                + "0000000000000000";

        /**
         * Test cipher.
         * @param pTest the test engine
         */
        void testTheCipher(final GCMSIVTest pTest)
        {
            pTest.testSIVCipher(new GCMSIVBlockCipher(), KEY_1, NONCE_1, EMPTY, DATA_1, EXPECTED_1);
            pTest.testSIVCipher(new GCMSIVBlockCipher(), KEY_1, NONCE_1, EMPTY, DATA_2, EXPECTED_2);
        }
    }

    /**
     * Main entry point.
     *
     * @param args the argyments
     */
    public static void main(String[] args)
    {
        runTest(new GCMSIVTest());
    }
}
