package org.bouncycastle.crypto.test;

import org.bouncycastle.crypto.StreamCipher;
import org.bouncycastle.crypto.engines.HC128Engine;
import org.bouncycastle.crypto.engines.HC256Engine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

/**
 * HC-128 and HC-256 Tests. Based on the test vectors in the official reference
 * papers, respectively:
 * <pre>
 * https://www.ecrypt.eu.org/stream/p3ciphers/hc/hc128_p3.pdf
 * https://www.ecrypt.eu.org/stream/p3ciphers/hc/hc256_p3.pdf
 * </pre>
 * See HCFamilyVecTest for a more exhaustive test based on the ecrypt vectors.
 */
public class HCFamilyTest
    extends SimpleTest
{
    private static final byte[] MSG = new byte[64];

    private static String[][] HC128_VerifiedTest =
        {
            {
                "Set 2, vector#  0",
                "00000000000000000000000000000000",
                "00000000000000000000000000000000",
                "82001573A003FD3B7FD72FFB0EAF63AA" +
                "C62F12DEB629DCA72785A66268EC758B" +
                "1EDB36900560898178E0AD009ABF1F49" +
                "1330DC1C246E3D6CB264F6900271D59C"
            },
            {
                "Set 6, vector#  0",
                "0053A6F94C9FF24598EB3E91E4378ADD",
                "0D74DB42A91077DE45AC137AE148AF16",
                "2E1ED12A8551C05AF41FF39D8F9DF933" +
                "122B5235D48FC2A6F20037E69BDBBCE8" +
                "05782EFC16C455A4B3FF06142317535E" +
                "F876104C32445138CB26EBC2F88A684C"
            },
            {
                "Set 6, vector#  1",
                "0558ABFE51A4F74A9DF04396E93C8FE2",
                "167DE44BB21980E74EB51C83EA51B81F",
                "4F864BF3C96D0363B1903F0739189138" +
                "F6ED2BC0AF583FEEA0CEA66BA7E06E63" +
                "FB28BF8B3CA0031D24ABB511C57DD17B" +
                "FC2861C32400072CB680DF2E58A5CECC"
            },
            {
                "Set 6, vector#  2",
                "0A5DB00356A9FC4FA2F5489BEE4194E7",
                "1F86ED54BB2289F057BE258CF35AC128",
                "82168AB0023B79AAF1E6B4D823855E14" +
                "A7084378036A951B1CFEF35173875ED8" +
                "6CB66AB8410491A08582BE40080C3102" +
                "193BA567F9E95D096C3CC60927DD7901"
            },
            {
                "Set 6, vector#  3",
                "0F62B5085BAE0154A7FA4DA0F34699EC",
                "288FF65DC42B92F960C72E95FC63CA31",
                "1CD8AEDDFE52E217E835D0B7E84E2922" +
                "D04B1ADBCA53C4522B1AA604C42856A9" +
                "0AF83E2614BCE65C0AECABDD8975B557" +
                "00D6A26D52FFF0888DA38F1DE20B77B7"
            }
        };

    private static String[][] HC256_VerifiedTest =
        {
            {
                "Set 2, vector#  0",
                "00000000000000000000000000000000",
                "00000000000000000000000000000000",
                "5B078985D8F6F30D42C5C02FA6B67951" +
                "53F06534801F89F24E74248B720B4818" +
                "CD9227ECEBCF4DBF8DBF6977E4AE14FA" +
                "E8504C7BC8A9F3EA6C0106F5327E6981"
            },
            {
                "Set 2, vector#  9",
                "09090909090909090909090909090909",
                "00000000000000000000000000000000",
                "F5C2926651AEED9AF1A9C2F04C03D081" +
                "2145B56AEA46EB283A25A4C9E3D8BEB4" +
                "821B418F06F2B9DCDF1A85AB8C02CD14" +
                "62E1BBCAEC9AB0E99AA6AFF918BA627C"
            },
            {
                "Set 2, vector#135",
                "87878787878787878787878787878787",
                "00000000000000000000000000000000",
                "CEC0C3852E3B98233EBCB975C10B1191" +
                "3C69F2275EB97A1402EDF16C6FBE19BE" +
                "79D65360445BCB63676E6553B609A065" +
                "0155C3B22DD1975AC0F3F65063A2E16E"
            },
            {
                "Set 6, vector#  0",
                "0053A6F94C9FF24598EB3E91E4378ADD" +
                "3083D6297CCF2275C81B6EC11467BA0D",
                "0D74DB42A91077DE45AC137AE148AF16" +
                "7DE44BB21980E74EB51C83EA51B81F86",
                "23D9E70A45EB0127884D66D9F6F23C01" +
                "D1F88AFD629270127247256C1FFF91E9" +
                "1A797BD98ADD23AE15BEE6EEA3CEFDBF" +
                "A3ED6D22D9C4F459DB10C40CDF4F4DFF"
            },
            {
                "Set 6, vector#  1",
                "0558ABFE51A4F74A9DF04396E93C8FE2" +
                "3588DB2E81D4277ACD2073C6196CBF12",
                "167DE44BB21980E74EB51C83EA51B81F" +
                "86ED54BB2289F057BE258CF35AC1288F",
                "C44B5262F2EAD9C018213127686DB742" +
                "A72D3F2D61D18F0F4E7DE5B4F7ADABE0" +
                "7E0C82033B139F02BAACB4E2F2D0BE30" +
                "110C3A8A2B621523756692877C905DD0"
            },
            {
                "Set 6, vector#  2",
                "0A5DB00356A9FC4FA2F5489BEE4194E7" +
                "3A8DE03386D92C7FD22578CB1E71C417",
                "1F86ED54BB2289F057BE258CF35AC128" +
                "8FF65DC42B92F960C72E95FC63CA3198",
                "9D13AA06122F4F03AE60D507701F1ED0" +
                "63D7530FF35EE76CAEDCBFB01D8A239E" +
                "FA4A44B272DE9B4092E2AD56E87C3A60" +
                "89F5A074D1F6E5B8FC6FABEE0C936F06"
            },
            {
                "Set 6, vector#  3",
                "0F62B5085BAE0154A7FA4DA0F34699EC" +
                "3F92E5388BDE3184D72A7DD02376C91C",
                "288FF65DC42B92F960C72E95FC63CA31" +
                "98FF66CD349B0269D0379E056CD33AA1",
                "C8632038DA61679C4685288B37D3E232" +
                "7BC2D28C266B041FE0CA0D3CFEED8FD5" +
                "753259BAB757168F85EA96ADABD823CA" +
                "4684E918423E091565713FEDDE2CCFE0"
            }
        };

    public String getName()
    {
        return "HC-128 and HC-256";
    }

    public void performTest()
    {
        StreamCipher hc = new HC256Engine();

        for (int i = 0; i != HC256_VerifiedTest.length; i++)
        {
            String[] test = HC256_VerifiedTest[i];
            HCTest(hc, "HC-256 - " + test[0], Hex.decode(test[1]), Hex.decode(test[2]), Hex.decode(test[3]));
        }

        hc = new HC128Engine();

        for (int i = 0; i != HC128_VerifiedTest.length; i++)
        {
            String[] test = HC128_VerifiedTest[i];
            HCTest(hc, "HC-128 - " + test[0], Hex.decode(test[1]), Hex.decode(test[2]), Hex.decode(test[3]));
        }
    }

    private void HCTest(StreamCipher hc, String test, byte[] key, byte[] IV, byte[] expected)
    {
        KeyParameter kp = new KeyParameter(key);
        ParametersWithIV ivp = new ParametersWithIV(kp, IV);

        hc.init(true, ivp);
        for (int i = 0; i < 64; i++)
        {
            if (hc.returnByte(MSG[i]) != expected[i])
            {
                fail(test + " failure at byte " + i);
            }
        }
    }

    public static void main(String[] args)
    {
        runTest(new HCFamilyTest());
    }
}
