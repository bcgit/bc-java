package org.bouncycastle.crypto.test;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.crypto.kems.SAKKEKEMExtractor;
import org.bouncycastle.crypto.kems.SAKKEKEMSGenerator;
import org.bouncycastle.crypto.params.SAKKEPrivateKeyParameters;
import org.bouncycastle.crypto.params.SAKKEPublicKeyParameters;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.FixedSecureRandom;
import org.bouncycastle.util.test.SimpleTest;

public class SAKKEKEMSTest
    extends SimpleTest
{
    public static void main(String[] args)
        throws Exception
    {
        SAKKEKEMSTest test = new SAKKEKEMSTest();
        test.performTest();
    }


    @Override
    public String getName()
    {
        return "SAKKE-KEMS Test";
    }

    @Override
    public void performTest()
        throws Exception
    {
        testTestVector();
        for (int i = 0; i < 1; ++i)
        {
            testRandom();
        }
    }

    private void testTestVector()
    {
        final BigInteger Px = new BigInteger(
            "53FC09EE332C29AD0A7990053ED9B52A2B1A2FD60AEC69C698B2F204B6FF7CBF" +
                "B5EDB6C0F6CE2308AB10DB9030B09E1043D5F22CDB9DFA55718BD9E7406CE890" +
                "9760AF765DD5BCCB337C86548B72F2E1A702C3397A60DE74A7C1514DBA66910D" +
                "D5CFB4CC80728D87EE9163A5B63F73EC80EC46C4967E0979880DC8ABEAE63895", 16
        );

        final BigInteger Py = new BigInteger(
            "0A8249063F6009F1F9F1F0533634A135D3E82016029906963D778D821E141178" +
                "F5EA69F4654EC2B9E7F7F5E5F0DE55F66B598CCF9A140B2E416CFF0CA9E032B9" +
                "70DAE117AD547C6CCAD696B5B7652FE0AC6F1E80164AA989492D979FC5A4D5F2" +
                "13515AD7E9CB99A980BDAD5AD5BB4636ADB9B5706A67DCDE75573FD71BEF16D7", 16
        );
        BigInteger g = new BigInteger(Hex.decode("66FC2A43 2B6EA392 148F1586 7D623068" +
            "               C6A87BD1 FB94C41E 27FABE65 8E015A87" +
            "               371E9474 4C96FEDA 449AE956 3F8BC446" +
            "               CBFDA85D 5D00EF57 7072DA8F 541721BE" +
            "               EE0FAED1 828EAB90 B99DFB01 38C78433" +
            "               55DF0460 B4A9FD74 B4F1A32B CAFA1FFA" +
            "               D682C033 A7942BCC E3720F20 B9B7B040" +
            "               3C8CAE87 B7A0042A CDE0FAB3 6461EA46"));
        BigInteger z = new BigInteger("AFF429D35F84B110D094803B3595A6E2998BC99F", 16);
        BigInteger Zx = new BigInteger(Hex.decode("5958EF1B1679BF099B3A030DF255AA6A23C1D8F143D4D23F753E69BD27A832F38CB4AD53DDEF"
            + "4260B0FE8BB45C4C1FF510EFFE300367A37B61F701D914AEF09724825FA0707D61A6DFF4FBD7273566CDDE352A0B04B7C16A78309BE"
            + "640697DE747613A5FC195E8B9F328852A579DB8F99B1D0034479EA9C5595F47C4B2F54FF2"));
        BigInteger Zy = new BigInteger(Hex.decode("1508D37514DCF7A8E143A6058C09A6BF2C9858CA37C258065AE6BF7532BC8B5B63383866E075"
            + "3C5AC0E72709F8445F2E6178E065857E0EDA10F68206B63505ED87E534FB2831FF957FB7DC619DAE61301EEACC2FDA3680EA499925" +
            "8A833CEA8FC67C6D19487FB449059F26CC8AAB655AB58B7CC796E24E9A394095754F5F8BAE"));
        BigInteger q = new BigInteger(Hex.decode("265EAEC7 C2958FF6 99718466 36B4195E" +
            "               905B0338 672D2098 6FA6B8D6 2CF8068B" +
            "               BD02AAC9 F8BF03C6 C8A1CC35 4C69672C" +
            "               39E46CE7 FDF22286 4D5B49FD 2999A9B4" +
            "               389B1921 CC9AD335 144AB173 595A0738" +
            "               6DABFD2A 0C614AA0 A9F3CF14 870F026A" +
            "               A7E535AB D5A5C7C7 FF38FA08 E2615F6C" +
            "               203177C4 2B1EB3A1 D99B601E BFAA17FB"));
//
        byte[] b = Hex.decode("323031312D30320074656C3A2B34343737303039303031323300");

        byte[] ssv = Hex.decode("123456789ABCDEF0123456789ABCDEF0");
        byte[] expectedR = Hex.decode("13EE3E1B8DAC5DB168B1CEB32F0566A4C273693F78BAFFA2A2EE6A686E6BD90F8206CCAB84E7F"
            + "42ED39BD4FB131012ECCA2ECD2119414560C17CAB46B956A80F58A3302EB3E2C9A228FBA7ED34D8ACA2392DA1FFB0B17B2320AE09AAEDF"
            + "D0235F6FE0EB65337A63F9CC97728B8E5AD0460FADE144369AA5B2166213247712096");

        BigInteger kbx = new BigInteger("93AF67E5007BA6E6A80DA793DA300FA4" +
            "B52D0A74E25E6E7B2B3D6EE9D18A9B5C" +
            "5023597BD82D8062D34019563BA1D25C" +
            "0DC56B7B979D74AA50F29FBF11CC2C93" +
            "F5DFCA615E609279F6175CEADB00B58C" +
            "6BEE1E7A2A47C4F0C456F05259A6FA94" +
            "A634A40DAE1DF593D4FECF688D5FC678" +
            "BE7EFC6DF3D6835325B83B2C6E69036B", 16);

        BigInteger kby = new BigInteger("155F0A27241094B04BFB0BDFAC6C670A" +
            "65C325D39A069F03659D44CA27D3BE8D" +
            "F311172B554160181CBE94A2A783320C" +
            "ED590BC42644702CF371271E496BF20F" +
            "588B78A1BC01ECBB6559934BDD2FB65D" +
            "2884318A33D1A42ADF5E33CC5800280B" +
            "28356497F87135BAB9612A1726042440" +
            "9AC15FEE996B744C332151235DECB0F5", 16);
//        BigInteger w = new BigInteger(Hex.decode("7D2A8438 E6291C64 9B6579EB 3B79EAE9" +
//            "48B1DE9E 5F7D1F40 70A08F8D B6B3C515" +
//            "6F2201AF FBB5CB9D 82AA3EC0 D0398B89" +
//            "ABC78A13 A760C0BF 3F77E63D 0DF3F1A3" +
//            "41A41B88 11DF197F D6CD0F00 3125606F" +
//            "4F109F40 0F7292A1 0D255E3C 0EBCCB42" +
//            "53FB182C 68F09CF6 CD9C4A53 DA6C74AD" +
//            "007AF36B 8BCA979D 5895E282 F483FCD6"));
//        BigInteger Rbx = new BigInteger(Hex.decode("44E8AD44 AB8592A6 A5A3DDCA 5CF896C7" +
//            "18043606 A01D650D EF37A01F 37C228C3" +
//            "32FC3173 54E2C274 D4DAF8AD 001054C7" +
//            "6CE57971 C6F4486D 57230432 61C506EB" +
//            "F5BE438F 53DE04F0 67C776E0 DD3B71A6" +
//            "29013328 3725A532 F21AF145 126DC1D7" +
//            "77ECC27B E50835BD 28098B8A 73D9F801" +
//            "D893793A 41FF5C49 B87E79F2 BE4D56CE"));
//        BigInteger Rby = new BigInteger(Hex.decode("557E134A D85BB1D4 B9CE4F8B E4B08A12" +
//            "BABF55B1 D6F1D7A6 38019EA2 8E15AB1C" +
//            "9F76375F DD1210D4 F4351B9A 009486B7" +
//            "F3ED46C9 65DED2D8 0DADE4F3 8C6721D5" +
//            "2C3AD103 A10EBD29 59248B4E F006836B" +
//            "F097448E 6107C9ED EE9FB704 823DF199" +
//            "F832C905 AE45F8A2 47A072D8 EF729EAB" +
//            "C5E27574 B07739B3 4BE74A53 2F747B86"));
        BigInteger p = new BigInteger(
            "997ABB1F0A563FDA65C61198DAD0657A416C0CE19CB48261BE9AE358B3E01A2E" +
                "F40AAB27E2FC0F1B228730D531A59CB0E791B39FF7C88A19356D27F4A666A6D0" +
                "E26C6487326B4CD4512AC5CD65681CE1B6AFF4A831852A82A7CF3C521C3C09AA" +
                "9F94D6AF56971F1FFCE3E82389857DB080C5DF10AC7ACE87666D807AFEA85FEB", 16
        );
        ECCurve.Fp curve = new ECCurve.Fp(
            p, // Prime p
            BigInteger.valueOf(-3).mod(p),             // a = -3
            BigInteger.ZERO, // ,
            g,// Order of the subgroup (from RFC 6509)
            BigInteger.ONE     // Cofactor = 1
        );
        ECPoint P = curve.createPoint(Px, Py);

        ECPoint computed_Z = P.multiply(z).normalize();
        isTrue(computed_Z.equals(curve.createPoint(Zx, Zy)));

        SecureRandom random = new FixedSecureRandom(new FixedSecureRandom.Source[]{new FixedSecureRandom.Data(ssv)});
        SAKKEPublicKeyParameters b_publicKey = new SAKKEPublicKeyParameters(new BigInteger(b), curve.createPoint(Zx, Zy));
        SAKKEKEMSGenerator generator = new SAKKEKEMSGenerator(random);
        SecretWithEncapsulation rlt = generator.generateEncapsulated(b_publicKey);


        SAKKEKEMExtractor extractor = new SAKKEKEMExtractor(new SAKKEPrivateKeyParameters(z, b_publicKey));
        byte[] test = extractor.extractSecret(rlt.getEncapsulation());
        isTrue(Arrays.areEqual(test, ssv));
    }

    private void testRandom()
    {
        SecureRandom random = new SecureRandom();
        byte[] ssv = new byte[16];
        random.nextBytes(ssv);
        SAKKEPrivateKeyParameters b_priv = new SAKKEPrivateKeyParameters(random);
        SAKKEPublicKeyParameters b_pub = b_priv.getPublicParams();
        SAKKEKEMSGenerator generator = new SAKKEKEMSGenerator(new FixedSecureRandom(new FixedSecureRandom.Source[]{new FixedSecureRandom.Data(ssv)}));
        SecretWithEncapsulation rlt = generator.generateEncapsulated(b_pub);
        SAKKEKEMExtractor extractor = new SAKKEKEMExtractor(b_priv);
        byte[] test = extractor.extractSecret(rlt.getEncapsulation());
        isTrue(Arrays.areEqual(test, ssv));
    }
}
