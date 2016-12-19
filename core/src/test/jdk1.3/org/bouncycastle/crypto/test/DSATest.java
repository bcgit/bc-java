package org.bouncycastle.crypto.test;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.digests.SHA224Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA3Digest;
import org.bouncycastle.crypto.generators.DSAKeyPairGenerator;
import org.bouncycastle.crypto.generators.DSAParametersGenerator;
import org.bouncycastle.crypto.params.DSAKeyGenerationParameters;
import org.bouncycastle.crypto.params.DSAParameterGenerationParameters;
import org.bouncycastle.crypto.params.DSAParameters;
import org.bouncycastle.crypto.params.DSAPrivateKeyParameters;
import org.bouncycastle.crypto.params.DSAPublicKeyParameters;
import org.bouncycastle.crypto.params.DSAValidationParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.signers.DSADigestSigner;
import org.bouncycastle.crypto.signers.DSASigner;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.FixedSecureRandom;
import org.bouncycastle.util.test.SimpleTest;
import org.bouncycastle.util.test.TestRandomBigInteger;
import org.bouncycastle.util.test.TestRandomData;

/**
 * Test based on FIPS 186-2, Appendix 5, an example of DSA, and FIPS 168-3 test vectors.
 */
public class DSATest
    extends SimpleTest
{
    byte[] k1 = Hex.decode("d5014e4b60ef2ba8b6211b4062ba3224e0427dd3");
    byte[] k2 = Hex.decode("345e8d05c075c3a508df729a1685690e68fcfb8c8117847e89063bca1f85d968fd281540b6e13bd1af989a1fbf17e06462bf511f9d0b140fb48ac1b1baa5bded");

    SecureRandom    random = new FixedSecureRandom(
        new FixedSecureRandom.Source[] { new FixedSecureRandom.Data(k1), new FixedSecureRandom.Data(k2) });

    byte[] keyData = Hex.decode("b5014e4b60ef2ba8b6211b4062ba3224e0427dd3");
    
    SecureRandom    keyRandom = new FixedSecureRandom(
                      new FixedSecureRandom.Source[] { new FixedSecureRandom.Data(keyData), new FixedSecureRandom.Data(keyData), new FixedSecureRandom.Data(Hex.decode("01020304"))});

    BigInteger  pValue = new BigInteger("8df2a494492276aa3d25759bb06869cbeac0d83afb8d0cf7cbb8324f0d7882e5d0762fc5b7210eafc2e9adac32ab7aac49693dfbf83724c2ec0736ee31c80291", 16);
    BigInteger  qValue = new BigInteger("c773218c737ec8ee993b4f2ded30f48edace915f", 16);

    public String getName()
    {
        return "DSA";
    }

    public void performTest()
    {
        BigInteger              r = new BigInteger("68076202252361894315274692543577577550894681403");
        BigInteger              s = new BigInteger("1089214853334067536215539335472893651470583479365");
        DSAParametersGenerator  pGen = new DSAParametersGenerator();

        pGen.init(512, 80, random);

        DSAParameters           params = pGen.generateParameters();
        DSAValidationParameters pValid = params.getValidationParameters();

        if (pValid.getCounter() != 105)
        {
            fail("Counter wrong");
        }

        if (!pValue.equals(params.getP()) || !qValue.equals(params.getQ()))
        {
            fail("p or q wrong");
        }

        DSAKeyPairGenerator         dsaKeyGen = new DSAKeyPairGenerator();
        DSAKeyGenerationParameters  genParam = new DSAKeyGenerationParameters(keyRandom, params);

        dsaKeyGen.init(genParam);

        AsymmetricCipherKeyPair  pair = dsaKeyGen.generateKeyPair();

        ParametersWithRandom param = new ParametersWithRandom(pair.getPrivate(), keyRandom);

        DSASigner dsa = new DSASigner();

        dsa.init(true, param);

        byte[] message = BigIntegers.asUnsignedByteArray(new BigInteger("968236873715988614170569073515315707566766479517"));
        BigInteger[] sig = dsa.generateSignature(message);

        if (!r.equals(sig[0]))
        {
            fail("r component wrong.", r, sig[0]);
        }

        if (!s.equals(sig[1]))
        {
            fail("s component wrong.", s, sig[1]);
        }

        dsa.init(false, pair.getPublic());

        if (!dsa.verifySignature(message, sig[0], sig[1]))
        {
            fail("verification fails");
        }

        //dsa2Test1();
        //dsa2Test2();
        //dsa2Test3();
        //dsa2Test4();

        testDSAsha3(224, new BigInteger("613202af2a7f77e02b11b5c3a5311cf6b412192bc0032aac3ec127faebfc6bd0", 16));
        testDSAsha3(256, new BigInteger("2450755c5e15a691b121bc833b97864e34a61ee025ecec89289c949c1858091e", 16));
        testDSAsha3(384, new BigInteger("7aad97c0b71bb1e1a6483b6948a03bbe952e4780b0cee699a11731f90d84ddd1", 16));
        testDSAsha3(512, new BigInteger("725ad64d923c668e64e7c3898b5efde484cab49ce7f98c2885d2a13a9e355ad4", 16));
    }

    private void testDSAsha3(int size, BigInteger s)
    {
        DSAParameters dsaParams = new DSAParameters(
            new BigInteger(
                        "F56C2A7D366E3EBDEAA1891FD2A0D099" +
                        "436438A673FED4D75F594959CFFEBCA7BE0FC72E4FE67D91" +
                        "D801CBA0693AC4ED9E411B41D19E2FD1699C4390AD27D94C" +
                        "69C0B143F1DC88932CFE2310C886412047BD9B1C7A67F8A2" +
                        "5909132627F51A0C866877E672E555342BDF9355347DBD43" +
                        "B47156B2C20BAD9D2B071BC2FDCF9757F75C168C5D9FC431" +
                        "31BE162A0756D1BDEC2CA0EB0E3B018A8B38D3EF2487782A" +
                        "EB9FBF99D8B30499C55E4F61E5C7DCEE2A2BB55BD7F75FCD" +
                        "F00E48F2E8356BDB59D86114028F67B8E07B127744778AFF" +
                        "1CF1399A4D679D92FDE7D941C5C85C5D7BFF91BA69F9489D" +
                        "531D1EBFA727CFDA651390F8021719FA9F7216CEB177BD75", 16),
            new BigInteger("C24ED361870B61E0D367F008F99F8A1F75525889C89DB1B673C45AF5867CB467", 16),
            new BigInteger(
                        "8DC6CC814CAE4A1C05A3E186A6FE27EA" +
                        "BA8CDB133FDCE14A963A92E809790CBA096EAA26140550C1" +
                        "29FA2B98C16E84236AA33BF919CD6F587E048C52666576DB" +
                        "6E925C6CBE9B9EC5C16020F9A44C9F1C8F7A8E611C1F6EC2" +
                        "513EA6AA0B8D0F72FED73CA37DF240DB57BBB27431D61869" +
                        "7B9E771B0B301D5DF05955425061A30DC6D33BB6D2A32BD0" +
                        "A75A0A71D2184F506372ABF84A56AEEEA8EB693BF29A6403" +
                        "45FA1298A16E85421B2208D00068A5A42915F82CF0B858C8" +
                        "FA39D43D704B6927E0B2F916304E86FB6A1B487F07D8139E" +
                        "428BB096C6D67A76EC0B8D4EF274B8A2CF556D279AD267CC" +
                        "EF5AF477AFED029F485B5597739F5D0240F67C2D948A6279", 16)
        );

        BigInteger x = new BigInteger("0CAF2EF547EC49C4F3A6FE6DF4223A174D01F2C115D49A6F73437C29A2A8458C", 16);

        BigInteger y = new BigInteger(
                    "2828003D7C747199143C370FDD07A286" +
                    "1524514ACC57F63F80C38C2087C6B795B62DE1C224BF8D1D" +
                    "1424E60CE3F5AE3F76C754A2464AF292286D873A7A30B7EA" +
                    "CBBC75AAFDE7191D9157598CDB0B60E0C5AA3F6EBE425500" +
                    "C611957DBF5ED35490714A42811FDCDEB19AF2AB30BEADFF" +
                    "2907931CEE7F3B55532CFFAEB371F84F01347630EB227A41" +
                    "9B1F3F558BC8A509D64A765D8987D493B007C4412C297CAF" +
                    "41566E26FAEE475137EC781A0DC088A26C8804A98C23140E" +
                    "7C936281864B99571EE95C416AA38CEEBB41FDBFF1EB1D1D" +
                    "C97B63CE1355257627C8B0FD840DDB20ED35BE92F08C49AE" +
                    "A5613957D7E5C7A6D5A5834B4CB069E0831753ECF65BA02B", 16);

        DSAPrivateKeyParameters priKey = new DSAPrivateKeyParameters(x, dsaParams);
        SecureRandom k = new FixedSecureRandom(
            new FixedSecureRandom.Source[] {
                new FixedSecureRandom.BigInteger(BigIntegers.asUnsignedByteArray(new BigInteger("72546832179840998877302529996971396893172522460793442785601695562409154906335"))),
                new FixedSecureRandom.Data(Hex.decode("01020304"))
            });

        byte[] M = Hex.decode("1BD4ED430B0F384B4E8D458EFF1A8A553286D7AC21CB2F6806172EF5F94A06AD");

        DSADigestSigner dsa = new DSADigestSigner(new DSASigner(), new SHA3Digest(size));

        dsa.init(true, new ParametersWithRandom(priKey, k));

        dsa.update(M, 0, M.length);

        byte[] encSig = dsa.generateSignature();

        ASN1Sequence sig = ASN1Sequence.getInstance(encSig);

        BigInteger r = new BigInteger("4864074fe30e6601268ee663440e4d9b703f62673419864e91e9edb0338ce510", 16);

        BigInteger sigR = ASN1Integer.getInstance(sig.getObjectAt(0)).getValue();
        if (!r.equals(sigR))
        {
            fail("r component wrong." + Strings.lineSeparator()
                + " expecting: " + r.toString(16) + Strings.lineSeparator()
                + " got      : " + sigR.toString(16));
        }

        BigInteger sigS = ASN1Integer.getInstance(sig.getObjectAt(1)).getValue();
        if (!s.equals(sigS))
        {
            fail("s component wrong." + Strings.lineSeparator()
                + " expecting: " + s.toString(16) + Strings.lineSeparator()
                + " got      : " + sigS.toString(16));
        }

        // Verify the signature
        DSAPublicKeyParameters pubKey = new DSAPublicKeyParameters(y, dsaParams);

        dsa.init(false, pubKey);

        dsa.update(M, 0, M.length);

        if (!dsa.verifySignature(encSig))
        {
            fail("signature fails");
        }
    }

    private void dsa2Test1()
    {
        byte[] seed = Hex.decode("ED8BEE8D1CB89229D2903CBF0E51EE7377F48698");

        DSAParametersGenerator pGen = new DSAParametersGenerator();

        pGen.init(new DSAParameterGenerationParameters(1024, 160, 80, new DSATestSecureRandom(seed)));

        DSAParameters params = pGen.generateParameters();

        DSAValidationParameters pv = params.getValidationParameters();

        if (pv.getCounter() != 5)
        {
            fail("counter incorrect");
        }

        if (!Arrays.areEqual(seed, pv.getSeed()))
        {
            fail("seed incorrect");
        }

        if (!params.getQ().equals(new BigInteger("E950511EAB424B9A19A2AEB4E159B7844C589C4F", 16)))
        {
            fail("Q incorrect");
        }

        if (!params.getP().equals(new BigInteger(
            "E0A67598CD1B763B" +
            "C98C8ABB333E5DDA0CD3AA0E5E1FB5BA8A7B4EABC10BA338" +
            "FAE06DD4B90FDA70D7CF0CB0C638BE3341BEC0AF8A7330A3" +
            "307DED2299A0EE606DF035177A239C34A912C202AA5F83B9" +
            "C4A7CF0235B5316BFC6EFB9A248411258B30B839AF172440" +
            "F32563056CB67A861158DDD90E6A894C72A5BBEF9E286C6B", 16)))
        {
            fail("P incorrect");
        }

        if (!params.getG().equals(new BigInteger(
            "D29D5121B0423C27" +
            "69AB21843E5A3240FF19CACC792264E3BB6BE4F78EDD1B15" +
            "C4DFF7F1D905431F0AB16790E1F773B5CE01C804E509066A" +
            "9919F5195F4ABC58189FD9FF987389CB5BEDF21B4DAB4F8B" +
            "76A055FFE2770988FE2EC2DE11AD92219F0B351869AC24DA" +
            "3D7BA87011A701CE8EE7BFE49486ED4527B7186CA4610A75", 16)))
        {
            fail("G incorrect");
        }

        DSAKeyPairGenerator kpGen = new DSAKeyPairGenerator();

        kpGen.init(new DSAKeyGenerationParameters(new TestRandomBigInteger("D0EC4E50BB290A42E9E355C73D8809345DE2E139", 16), params));

        AsymmetricCipherKeyPair kp = kpGen.generateKeyPair();

        DSAPublicKeyParameters pub = (DSAPublicKeyParameters)kp.getPublic();
        DSAPrivateKeyParameters priv = (DSAPrivateKeyParameters)kp.getPrivate();

        if (!pub.getY().equals(new BigInteger(
            "25282217F5730501" +
            "DD8DBA3EDFCF349AAFFEC20921128D70FAC44110332201BB" +
            "A3F10986140CBB97C726938060473C8EC97B4731DB004293" +
            "B5E730363609DF9780F8D883D8C4D41DED6A2F1E1BBBDC97" +
            "9E1B9D6D3C940301F4E978D65B19041FCF1E8B518F5C0576" +
            "C770FE5A7A485D8329EE2914A2DE1B5DA4A6128CEAB70F79", 16)))
        {
            fail("Y value incorrect");
        }

        if (!priv.getX().equals(
            new BigInteger("D0EC4E50BB290A42E9E355C73D8809345DE2E139", 16)))
        {
            fail("X value incorrect");
        }

        DSASigner signer = new DSASigner();

        signer.init(true, new ParametersWithRandom(kp.getPrivate(), new FixedSecureRandom(
            new FixedSecureRandom.Source[] {
                new FixedSecureRandom.BigInteger("349C55648DCF992F3F33E8026CFAC87C1D2BA075"),
                new FixedSecureRandom.Data(Hex.decode("01020304")) })));

        byte[] msg = Hex.decode("A9993E364706816ABA3E25717850C26C9CD0D89D");

        BigInteger[] sig = signer.generateSignature(msg);

        if (!sig[0].equals(new BigInteger("636155AC9A4633B4665D179F9E4117DF68601F34", 16)))
        {
            fail("R value incorrect");
        }

        if (!sig[1].equals(new BigInteger("6C540B02D9D4852F89DF8CFC99963204F4347704", 16)))
        {
            fail("S value incorrect");
        }

        signer.init(false, kp.getPublic());

        if (!signer.verifySignature(msg, sig[0], sig[1]))
        {
            fail("signature not verified");
        }

    }

    private void dsa2Test2()
        {
            byte[] seed = Hex.decode("5AFCC1EFFC079A9CCA6ECA86D6E3CC3B18642D9BE1CC6207C84002A9");

            DSAParametersGenerator pGen = new DSAParametersGenerator(new SHA224Digest());

            pGen.init(new DSAParameterGenerationParameters(2048, 224, 80, new DSATestSecureRandom(seed)));

            DSAParameters params = pGen.generateParameters();

            DSAValidationParameters pv = params.getValidationParameters();

            if (pv.getCounter() != 21)
            {
                fail("counter incorrect");
            }

            if (!Arrays.areEqual(seed, pv.getSeed()))
            {
                fail("seed incorrect");
            }

            if (!params.getQ().equals(new BigInteger("90EAF4D1AF0708B1B612FF35E0A2997EB9E9D263C9CE659528945C0D", 16)))
            {
                fail("Q incorrect");
            }

            if (!params.getP().equals(new BigInteger(
                "C196BA05AC29E1F9C3C72D56DFFC6154" +
                "A033F1477AC88EC37F09BE6C5BB95F51C296DD20D1A28A06" +
                "7CCC4D4316A4BD1DCA55ED1066D438C35AEBAABF57E7DAE4" +
                "28782A95ECA1C143DB701FD48533A3C18F0FE23557EA7AE6" +
                "19ECACC7E0B51652A8776D02A425567DED36EABD90CA33A1" +
                "E8D988F0BBB92D02D1D20290113BB562CE1FC856EEB7CDD9" +
                "2D33EEA6F410859B179E7E789A8F75F645FAE2E136D252BF" +
                "FAFF89528945C1ABE705A38DBC2D364AADE99BE0D0AAD82E" +
                "5320121496DC65B3930E38047294FF877831A16D5228418D" +
                "E8AB275D7D75651CEFED65F78AFC3EA7FE4D79B35F62A040" +
                "2A1117599ADAC7B269A59F353CF450E6982D3B1702D9CA83", 16)))
            {
                fail("P incorrect");
            }

            if (!params.getG().equals(new BigInteger(
                "A59A749A11242C58C894E9E5A91804E8"+
                "FA0AC64B56288F8D47D51B1EDC4D65444FECA0111D78F35F"+
                "C9FDD4CB1F1B79A3BA9CBEE83A3F811012503C8117F98E50"+
                "48B089E387AF6949BF8784EBD9EF45876F2E6A5A495BE64B"+
                "6E770409494B7FEE1DBB1E4B2BC2A53D4F893D418B715959"+
                "2E4FFFDF6969E91D770DAEBD0B5CB14C00AD68EC7DC1E574"+
                "5EA55C706C4A1C5C88964E34D09DEB753AD418C1AD0F4FDF"+
                "D049A955E5D78491C0B7A2F1575A008CCD727AB376DB6E69"+
                "5515B05BD412F5B8C2F4C77EE10DA48ABD53F5DD498927EE"+
                "7B692BBBCDA2FB23A516C5B4533D73980B2A3B60E384ED20"+
                "0AE21B40D273651AD6060C13D97FD69AA13C5611A51B9085", 16)))
            {
                fail("G incorrect");
            }

            DSAKeyPairGenerator kpGen = new DSAKeyPairGenerator();

            kpGen.init(new DSAKeyGenerationParameters(new TestRandomData(Hex.decode("00D0F09ED3E2568F6CADF9224117DA2AEC5A4300E009DE1366023E17")), params));

            AsymmetricCipherKeyPair kp = kpGen.generateKeyPair();

            DSAPublicKeyParameters pub = (DSAPublicKeyParameters)kp.getPublic();
            DSAPrivateKeyParameters priv = (DSAPrivateKeyParameters)kp.getPrivate();

            if (!pub.getY().equals(new BigInteger(
                "70035C9A3B225B258F16741F3941FBF0" +
                "6F3D056CD7BD864604CBB5EE9DD85304EE8E8E4ABD5E9032" +
                "11DDF25CE149075510ACE166970AFDC7DF552B7244F342FA" +
                "02F7A621405B754909D757F97290E1FE5036E904CF593446" +
                "0C046D95659821E1597ED9F2B1F0E20863A6BBD0CE74DACB" +
                "A5D8C68A90B29C2157CDEDB82EC12B81EE3068F9BF5F7F34" +
                "6ECA41ED174CCCD7D154FA4F42F80FFE1BF46AE9D8125DEB" +
                "5B4BA08A72BDD86596DBEDDC9550FDD650C58F5AE5133509" +
                "A702F79A31ECB490F7A3C5581631F7C5BE4FF7F9E9F27FA3" +
                "90E47347AD1183509FED6FCF198BA9A71AB3335B4F38BE8D" +
                "15496A00B6DC2263E20A5F6B662320A3A1EC033AA61E3B68", 16)))
            {
                fail("Y value incorrect");
            }

            if (!priv.getX().equals(
                new BigInteger("00D0F09ED3E2568F6CADF9224117DA2AEC5A4300E009DE1366023E17", 16)))
            {
                fail("X value incorrect");
            }

            DSASigner signer = new DSASigner();

            signer.init(true, new ParametersWithRandom(kp.getPrivate(), new FixedSecureRandom(
                new FixedSecureRandom.Source[] {
                    new FixedSecureRandom.BigInteger(Hex.decode("735959CC4463B8B440E407EECA8A473BF6A6D1FE657546F67D401F05")),
                    new FixedSecureRandom.Data(Hex.decode("01020304"))
                })));

            byte[] msg = Hex.decode("23097D223405D8228642A477BDA255B32AADBCE4BDA0B3F7E36C9DA7");

            BigInteger[] sig = signer.generateSignature(msg);

            if (!sig[0].equals(new BigInteger("4400138D05F9639CAF54A583CAAF25D2B76D0C3EAD752CE17DBC85FE", 16)))
            {
                fail("R value incorrect");
            }

            if (!sig[1].equals(new BigInteger("874D4F12CB13B61732D398445698CFA9D92381D938AA57EE2C9327B3", 16)))
            {
                fail("S value incorrect");
            }

            signer.init(false, kp.getPublic());

            if (!signer.verifySignature(msg, sig[0], sig[1]))
            {
                fail("signature not verified");
            }
        }

    private void dsa2Test3()
    {
        byte[] seed = Hex.decode("4783081972865EA95D43318AB2EAF9C61A2FC7BBF1B772A09017BDF5A58F4FF0");

        DSAParametersGenerator pGen = new DSAParametersGenerator(new SHA256Digest());

        pGen.init(new DSAParameterGenerationParameters(2048, 256, 80, new DSATestSecureRandom(seed)));

        DSAParameters params = pGen.generateParameters();

        DSAValidationParameters pv = params.getValidationParameters();

        if (pv.getCounter() != 12)
        {
            fail("counter incorrect");
        }

        if (!Arrays.areEqual(seed, pv.getSeed()))
        {
            fail("seed incorrect");
        }

        if (!params.getQ().equals(new BigInteger("C24ED361870B61E0D367F008F99F8A1F75525889C89DB1B673C45AF5867CB467", 16)))
        {
            fail("Q incorrect");
        }

        if (!params.getP().equals(new BigInteger(
            "F56C2A7D366E3EBDEAA1891FD2A0D099" +
            "436438A673FED4D75F594959CFFEBCA7BE0FC72E4FE67D91" +
            "D801CBA0693AC4ED9E411B41D19E2FD1699C4390AD27D94C" +
            "69C0B143F1DC88932CFE2310C886412047BD9B1C7A67F8A2" +
            "5909132627F51A0C866877E672E555342BDF9355347DBD43" +
            "B47156B2C20BAD9D2B071BC2FDCF9757F75C168C5D9FC431" +
            "31BE162A0756D1BDEC2CA0EB0E3B018A8B38D3EF2487782A" +
            "EB9FBF99D8B30499C55E4F61E5C7DCEE2A2BB55BD7F75FCD" +
            "F00E48F2E8356BDB59D86114028F67B8E07B127744778AFF" +
            "1CF1399A4D679D92FDE7D941C5C85C5D7BFF91BA69F9489D" +
            "531D1EBFA727CFDA651390F8021719FA9F7216CEB177BD75", 16)))
        {
            fail("P incorrect");
        }

        if (!params.getG().equals(new BigInteger(
            "8DC6CC814CAE4A1C05A3E186A6FE27EA" +
            "BA8CDB133FDCE14A963A92E809790CBA096EAA26140550C1" +
            "29FA2B98C16E84236AA33BF919CD6F587E048C52666576DB" +
            "6E925C6CBE9B9EC5C16020F9A44C9F1C8F7A8E611C1F6EC2" +
            "513EA6AA0B8D0F72FED73CA37DF240DB57BBB27431D61869" +
            "7B9E771B0B301D5DF05955425061A30DC6D33BB6D2A32BD0" +
            "A75A0A71D2184F506372ABF84A56AEEEA8EB693BF29A6403" +
            "45FA1298A16E85421B2208D00068A5A42915F82CF0B858C8" +
            "FA39D43D704B6927E0B2F916304E86FB6A1B487F07D8139E" +
            "428BB096C6D67A76EC0B8D4EF274B8A2CF556D279AD267CC" +
            "EF5AF477AFED029F485B5597739F5D0240F67C2D948A6279", 16)))
        {
            fail("G incorrect");
        }

        DSAKeyPairGenerator kpGen = new DSAKeyPairGenerator();

        kpGen.init(new DSAKeyGenerationParameters(new TestRandomData(Hex.decode("0CAF2EF547EC49C4F3A6FE6DF4223A174D01F2C115D49A6F73437C29A2A8458C")), params));

        AsymmetricCipherKeyPair kp = kpGen.generateKeyPair();

        DSAPublicKeyParameters pub = (DSAPublicKeyParameters)kp.getPublic();
        DSAPrivateKeyParameters priv = (DSAPrivateKeyParameters)kp.getPrivate();

        if (!pub.getY().equals(new BigInteger(
            "2828003D7C747199143C370FDD07A286" +
            "1524514ACC57F63F80C38C2087C6B795B62DE1C224BF8D1D" +
            "1424E60CE3F5AE3F76C754A2464AF292286D873A7A30B7EA" +
            "CBBC75AAFDE7191D9157598CDB0B60E0C5AA3F6EBE425500" +
            "C611957DBF5ED35490714A42811FDCDEB19AF2AB30BEADFF" +
            "2907931CEE7F3B55532CFFAEB371F84F01347630EB227A41" +
            "9B1F3F558BC8A509D64A765D8987D493B007C4412C297CAF" +
            "41566E26FAEE475137EC781A0DC088A26C8804A98C23140E" +
            "7C936281864B99571EE95C416AA38CEEBB41FDBFF1EB1D1D" +
            "C97B63CE1355257627C8B0FD840DDB20ED35BE92F08C49AE" +
            "A5613957D7E5C7A6D5A5834B4CB069E0831753ECF65BA02B", 16)))
        {
            fail("Y value incorrect");
        }

        if (!priv.getX().equals(
            new BigInteger("0CAF2EF547EC49C4F3A6FE6DF4223A174D01F2C115D49A6F73437C29A2A8458C", 16)))
        {
            fail("X value incorrect");
        }

        DSASigner signer = new DSASigner();

        signer.init(true, new ParametersWithRandom(kp.getPrivate(), new FixedSecureRandom(
            new FixedSecureRandom.Source[] {
                new FixedSecureRandom.BigInteger(Hex.decode("0CAF2EF547EC49C4F3A6FE6DF4223A174D01F2C115D49A6F73437C29A2A8458C")),
                new FixedSecureRandom.Data(Hex.decode("01020304"))
            })));

        byte[] msg = Hex.decode("BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD");

        BigInteger[] sig = signer.generateSignature(msg);

        if (!sig[0].equals(new BigInteger("315C875DCD4850E948B8AC42824E9483A32D5BA5ABE0681B9B9448D444F2BE3C", 16)))
        {
            fail("R value incorrect");
        }

        if (!sig[1].equals(new BigInteger("89718D12E54A8D9ED066E4A55F7ED5A2229CD23B9A3CEE78F83ED6AA61F6BCB9", 16)))
        {
            fail("S value incorrect");
        }

        signer.init(false, kp.getPublic());

        if (!signer.verifySignature(msg, sig[0], sig[1]))
        {
            fail("signature not verified");
        }
    }

    private void dsa2Test4()
    {
        byte[] seed = Hex.decode("193AFCA7C1E77B3C1ECC618C81322E47B8B8B997C9C83515C59CC446C2D9BD47");

        DSAParametersGenerator pGen = new DSAParametersGenerator(new SHA256Digest());

        pGen.init(new DSAParameterGenerationParameters(3072, 256, 80, new DSATestSecureRandom(seed)));

        DSAParameters params = pGen.generateParameters();

        DSAValidationParameters pv = params.getValidationParameters();

        if (pv.getCounter() != 20)
        {
            fail("counter incorrect");
        }

        if (!Arrays.areEqual(seed, pv.getSeed()))
        {
            fail("seed incorrect");
        }

        if (!params.getQ().equals(new BigInteger("CFA0478A54717B08CE64805B76E5B14249A77A4838469DF7F7DC987EFCCFB11D", 16)))
        {
            fail("Q incorrect");
        }

        if (!params.getP().equals(new BigInteger(
            "90066455B5CFC38F9CAA4A48B4281F292C260FEEF01FD610" +
            "37E56258A7795A1C7AD46076982CE6BB956936C6AB4DCFE0" +
            "5E6784586940CA544B9B2140E1EB523F009D20A7E7880E4E" +
            "5BFA690F1B9004A27811CD9904AF70420EEFD6EA11EF7DA1" +
            "29F58835FF56B89FAA637BC9AC2EFAAB903402229F491D8D" +
            "3485261CD068699B6BA58A1DDBBEF6DB51E8FE34E8A78E54" +
            "2D7BA351C21EA8D8F1D29F5D5D15939487E27F4416B0CA63" +
            "2C59EFD1B1EB66511A5A0FBF615B766C5862D0BD8A3FE7A0" +
            "E0DA0FB2FE1FCB19E8F9996A8EA0FCCDE538175238FC8B0E" +
            "E6F29AF7F642773EBE8CD5402415A01451A840476B2FCEB0" +
            "E388D30D4B376C37FE401C2A2C2F941DAD179C540C1C8CE0" +
            "30D460C4D983BE9AB0B20F69144C1AE13F9383EA1C08504F" +
            "B0BF321503EFE43488310DD8DC77EC5B8349B8BFE97C2C56" +
            "0EA878DE87C11E3D597F1FEA742D73EEC7F37BE43949EF1A" +
            "0D15C3F3E3FC0A8335617055AC91328EC22B50FC15B941D3" +
            "D1624CD88BC25F3E941FDDC6200689581BFEC416B4B2CB73", 16)))
        {
            fail("P incorrect");
        }

        if (!params.getG().equals(new BigInteger(
            "5E5CBA992E0A680D885EB903AEA78E4A45A469103D448EDE" +
            "3B7ACCC54D521E37F84A4BDD5B06B0970CC2D2BBB715F7B8" +
            "2846F9A0C393914C792E6A923E2117AB805276A975AADB52" +
            "61D91673EA9AAFFEECBFA6183DFCB5D3B7332AA19275AFA1" +
            "F8EC0B60FB6F66CC23AE4870791D5982AAD1AA9485FD8F4A" +
            "60126FEB2CF05DB8A7F0F09B3397F3937F2E90B9E5B9C9B6" +
            "EFEF642BC48351C46FB171B9BFA9EF17A961CE96C7E7A7CC" +
            "3D3D03DFAD1078BA21DA425198F07D2481622BCE45969D9C" +
            "4D6063D72AB7A0F08B2F49A7CC6AF335E08C4720E31476B6" +
            "7299E231F8BD90B39AC3AE3BE0C6B6CACEF8289A2E2873D5" +
            "8E51E029CAFBD55E6841489AB66B5B4B9BA6E2F784660896" +
            "AFF387D92844CCB8B69475496DE19DA2E58259B090489AC8" +
            "E62363CDF82CFD8EF2A427ABCD65750B506F56DDE3B98856" +
            "7A88126B914D7828E2B63A6D7ED0747EC59E0E0A23CE7D8A" +
            "74C1D2C2A7AFB6A29799620F00E11C33787F7DED3B30E1A2" +
            "2D09F1FBDA1ABBBFBF25CAE05A13F812E34563F99410E73B", 16)))
        {
            fail("G incorrect");
        }

        DSAKeyPairGenerator kpGen = new DSAKeyPairGenerator();

        kpGen.init(new DSAKeyGenerationParameters(new TestRandomData(Hex.decode("3ABC1587297CE7B9EA1AD6651CF2BC4D7F92ED25CABC8553F567D1B40EBB8764")), params));

        AsymmetricCipherKeyPair kp = kpGen.generateKeyPair();

        DSAPublicKeyParameters pub = (DSAPublicKeyParameters)kp.getPublic();
        DSAPrivateKeyParameters priv = (DSAPrivateKeyParameters)kp.getPrivate();

        if (!pub.getY().equals(new BigInteger(
            "8B891C8692D3DE875879390F2698B26FBECCA6B075535DCE" +
            "6B0C862577F9FA0DEF6074E7A7624121224A595896ABD4CD" +
            "A56B2CEFB942E025D2A4282FFAA98A48CDB47E1A6FCB5CFB" +
            "393EF35AF9DF913102BB303C2B5C36C3F8FC04ED7B8B69FE" +
            "FE0CF3E1FC05CFA713B3435B2656E913BA8874AEA9F93600" +
            "6AEB448BCD005D18EC3562A33D04CF25C8D3D69844343442" +
            "FA3DB7DE618C5E2DA064573E61E6D5581BFB694A23AC87FD" +
            "5B52D62E954E1376DB8DDB524FFC0D469DF978792EE44173" +
            "8E5DB05A7DC43E94C11A2E7A4FBE383071FA36D2A7EC8A93" +
            "88FE1C4F79888A99D3B6105697C2556B79BB4D7E781CEBB3" +
            "D4866AD825A5E830846072289FDBC941FA679CA82F5F78B7" +
            "461B2404DB883D215F4E0676CF5493950AC5591697BFEA8D" +
            "1EE6EC016B89BA51CAFB5F9C84C989FA117375E94578F28B" +
            "E0B34CE0545DA46266FD77F62D8F2CEE92AB77012AFEBC11" +
            "008985A821CD2D978C7E6FE7499D1AAF8DE632C21BB48CA5" +
            "CBF9F31098FD3FD3854C49A65D9201744AACE540354974F9", 16)))
        {
            fail("Y value incorrect");
        }

        if (!priv.getX().equals(
            new BigInteger("3ABC1587297CE7B9EA1AD6651CF2BC4D7F92ED25CABC8553F567D1B40EBB8764", 16)))
        {
            fail("X value incorrect");
        }

        DSASigner signer = new DSASigner();

        signer.init(true, new ParametersWithRandom(kp.getPrivate(), new FixedSecureRandom(
            new FixedSecureRandom.Source[]
                { new FixedSecureRandom.BigInteger("A6902C1E6E3943C5628061588A8B007BCCEA91DBF12915483F04B24AB0678BEE"),
                  new FixedSecureRandom.Data(Hex.decode("01020304")) })));

        byte[] msg = Hex.decode("BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD");

        BigInteger[] sig = signer.generateSignature(msg);

        if (!sig[0].equals(new BigInteger("5F184E645A38BE8FB4A6871B6503A9D12924C7ABE04B71410066C2ECA6E3BE3E", 16)))
        {
            fail("R value incorrect");
        }

        if (!sig[1].equals(new BigInteger("91EB0C7BA3D4B9B60B825C3D9F2CADA8A2C9D7723267B033CBCDCF8803DB9C18", 16)))
        {
            fail("S value incorrect");
        }

        signer.init(false, kp.getPublic());

        if (!signer.verifySignature(msg, sig[0], sig[1]))
        {
            fail("signature not verified");
        }
    }

    public static void main(
        String[]    args)
    {
        runTest(new DSATest());
    }

    private class DSATestSecureRandom
        extends TestRandomData
    {
        private boolean first = true;

        public DSATestSecureRandom(byte[] value)
        {
            super(value);
        }

       public void nextBytes(byte[] bytes)
       {
           if (first)
           {
               super.nextBytes(bytes);
               first = false;
           }
           else
           {
               bytes[bytes.length - 1] = 2;
           }
       }
    }
}
