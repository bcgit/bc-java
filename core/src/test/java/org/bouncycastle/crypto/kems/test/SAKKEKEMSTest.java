package org.bouncycastle.crypto.kems.test;

import java.math.BigInteger;


import org.bouncycastle.crypto.kems.SAKKEKEMSGenerator;
import org.bouncycastle.crypto.kems.SAKKEUtils;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;
import org.junit.Assert;

public class SAKKEKEMSTest
    extends SimpleTest
{
    public static void main(String[] args)
        throws Exception
    {
        SAKKEKEMSTest test = new SAKKEKEMSTest();
        test.performTest();
        // Expected Rb values
//        BigInteger expectedRbx = new BigInteger("44E8AD44AB8592A6A5A3DDCA5CF896C718043606A01D650DEF37A01F37C228C332FC317354E2C274D4DAF8AD001054C7...
//            BigInteger expectedRby = new BigInteger("557E134AD85BB1D4B9CE4F8BE4B08A12BABF55B1D6F1D7A638019EA28E15AB1C9F76375FDD1210D4F4351B9A009486B7...
//
//            // Instantiate SAKKE KEM Generator
//            SAKKEKEMSGenerator kem = new SAKKEKEMSGenerator();
//        EncapsulatedData encapsulatedData = kem.encapsulate(SSV);
//
//        // Validate results
//        boolean testPassed = expectedRbx.equals(encapsulatedData.getRbx()) && expectedRby.equals(encapsulatedData.getRby());

        //System.out.println("SAKKE KEM Test " + (testPassed ? "PASSED" : "FAILED"));
    }

    private static byte[] hexStringToByteArray(String s)
    {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2)
        {
            data[i / 2] = (byte)((Character.digit(s.charAt(i), 16) << 4)
                + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }

    @Override
    public String getName()
    {
        return null;
    }

    @Override
    public void performTest()
        throws Exception
    {
//        BigInteger z = new BigInteger("AFF429D35F84B110D094803B3595A6E2998BC99F");
//        BigInteger Zx = new BigInteger("5958EF1B1679BF099B3A030DF255AA6A23C1D8F143D4D23F753E69BD27A832F38CB4AD53DDEF"
//            + "4260B0FE8BB45C4C1FF510EFFE300367A37B61F701D914AEF09724825FA0707D61A6DFF4FBD7273566CDDE352A0B04B7C16A78309BE"
//            + "640697DE747613A5FC195E8B9F328852A579DB8F99B1D0034479EA9C5595F47C4B2F54FF2");
//        BigInteger Zy = new BigInteger("1508D37514DCF7A8E143A6058C09A6BF2C9858CA37C258065AE6BF7532BC8B5B63383866E075"
//            + "3C5AC0E72709F8445F2E6178E065857E0EDA10F68206B63505ED87E534FB2831FF957FB7DC619DAE61301EEACC2FDA3680EA499925" +
//            "8A833CEA8FC67C6D19487FB449059F26CC8AAB655AB58B7CC796E24E9A394095754F5F8BAE");
//
        byte[] b = Hex.decode("323031312D30320074656C3A2B34343737303039303031323300");

        byte[] SSV = Hex.decode("123456789ABCDEF0123456789ABCDEF0");
        byte[] expectedR = Hex.decode("13EE3E1B8DAC5DB168B1CEB32F0566A4C273693F78BAFFA2A2EE6A686E6BD90F8206CCAB84E7F"
            + "42ED39BD4FB131012ECCA2ECD2119414560C17CAB46B956A80F58A3302EB3E2C9A228FBA7ED34D8ACA2392DA1FFB0B17B2320AE09AAEDF"
            + "D0235F6FE0EB65337A63F9CC97728B8E5AD0460FADE144369AA5B2166213247712096");

        BigInteger r = SAKKEUtils.hashToIntegerRange(Arrays.concatenate(SSV, b), BigInteger.valueOf(1024));

        System.out.println("r:" +new String(Hex.encode(r.toByteArray())));

        System.out.println("r:" +new String(Hex.encode(expectedR)));

        Assert.assertTrue(Arrays.areEqual(r.toByteArray(), expectedR));
    }
}
