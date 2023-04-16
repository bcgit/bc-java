package org.bouncycastle.crypto.test;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X962NamedCurves;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.BasicAgreement;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoServiceConstraintsException;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.DSA;
import org.bouncycastle.crypto.RawAgreement;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.agreement.DHAgreement;
import org.bouncycastle.crypto.agreement.DHBasicAgreement;
import org.bouncycastle.crypto.agreement.DHStandardGroups;
import org.bouncycastle.crypto.agreement.DHUnifiedAgreement;
import org.bouncycastle.crypto.agreement.ECDHBasicAgreement;
import org.bouncycastle.crypto.agreement.ECDHCBasicAgreement;
import org.bouncycastle.crypto.agreement.ECDHCStagedAgreement;
import org.bouncycastle.crypto.agreement.ECDHCUnifiedAgreement;
import org.bouncycastle.crypto.agreement.ECMQVBasicAgreement;
import org.bouncycastle.crypto.agreement.ECVKOAgreement;
import org.bouncycastle.crypto.agreement.MQVBasicAgreement;
import org.bouncycastle.crypto.agreement.X25519Agreement;
import org.bouncycastle.crypto.agreement.X448Agreement;
import org.bouncycastle.crypto.agreement.XDHBasicAgreement;
import org.bouncycastle.crypto.agreement.XDHUnifiedAgreement;
import org.bouncycastle.crypto.constraints.BitsOfSecurityConstraint;
import org.bouncycastle.crypto.constraints.LegacyBitsOfSecurityConstraint;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.engines.CramerShoupCoreEngine;
import org.bouncycastle.crypto.engines.ElGamalEngine;
import org.bouncycastle.crypto.engines.NaccacheSternEngine;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.engines.SM2Engine;
import org.bouncycastle.crypto.generators.CramerShoupKeyPairGenerator;
import org.bouncycastle.crypto.generators.CramerShoupParametersGenerator;
import org.bouncycastle.crypto.generators.DHBasicKeyPairGenerator;
import org.bouncycastle.crypto.generators.DHKeyPairGenerator;
import org.bouncycastle.crypto.generators.DSAKeyPairGenerator;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator;
import org.bouncycastle.crypto.generators.Ed448KeyPairGenerator;
import org.bouncycastle.crypto.generators.ElGamalKeyPairGenerator;
import org.bouncycastle.crypto.generators.GOST3410KeyPairGenerator;
import org.bouncycastle.crypto.generators.KDF2BytesGenerator;
import org.bouncycastle.crypto.generators.NaccacheSternKeyPairGenerator;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.generators.X25519KeyPairGenerator;
import org.bouncycastle.crypto.generators.X448KeyPairGenerator;
import org.bouncycastle.crypto.kems.RSAKEMExtractor;
import org.bouncycastle.crypto.kems.RSAKEMGenerator;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.CramerShoupKeyGenerationParameters;
import org.bouncycastle.crypto.params.DHKeyGenerationParameters;
import org.bouncycastle.crypto.params.DHMQVPrivateParameters;
import org.bouncycastle.crypto.params.DHMQVPublicParameters;
import org.bouncycastle.crypto.params.DHPrivateKeyParameters;
import org.bouncycastle.crypto.params.DHPublicKeyParameters;
import org.bouncycastle.crypto.params.DHUPrivateParameters;
import org.bouncycastle.crypto.params.DHUPublicParameters;
import org.bouncycastle.crypto.params.DSAKeyGenerationParameters;
import org.bouncycastle.crypto.params.DSAParameters;
import org.bouncycastle.crypto.params.DSAPrivateKeyParameters;
import org.bouncycastle.crypto.params.DSAPublicKeyParameters;
import org.bouncycastle.crypto.params.ECDHUPrivateParameters;
import org.bouncycastle.crypto.params.ECDHUPublicParameters;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters;
import org.bouncycastle.crypto.params.Ed448KeyGenerationParameters;
import org.bouncycastle.crypto.params.ElGamalKeyGenerationParameters;
import org.bouncycastle.crypto.params.ElGamalParameters;
import org.bouncycastle.crypto.params.GOST3410KeyGenerationParameters;
import org.bouncycastle.crypto.params.GOST3410Parameters;
import org.bouncycastle.crypto.params.MQVPrivateParameters;
import org.bouncycastle.crypto.params.MQVPublicParameters;
import org.bouncycastle.crypto.params.NaccacheSternKeyGenerationParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.params.ParametersWithUKM;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.params.X25519KeyGenerationParameters;
import org.bouncycastle.crypto.params.X448KeyGenerationParameters;
import org.bouncycastle.crypto.params.XDHUPrivateParameters;
import org.bouncycastle.crypto.params.XDHUPublicParameters;
import org.bouncycastle.crypto.signers.DSASigner;
import org.bouncycastle.crypto.signers.DSTU4145Signer;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.signers.ECGOST3410Signer;
import org.bouncycastle.crypto.signers.Ed25519Signer;
import org.bouncycastle.crypto.signers.Ed25519ctxSigner;
import org.bouncycastle.crypto.signers.Ed25519phSigner;
import org.bouncycastle.crypto.signers.Ed448Signer;
import org.bouncycastle.crypto.signers.Ed448phSigner;
import org.bouncycastle.crypto.signers.GOST3410Signer;
import org.bouncycastle.crypto.signers.GenericSigner;
import org.bouncycastle.crypto.signers.ISO9796d2PSSSigner;
import org.bouncycastle.crypto.signers.ISO9796d2Signer;
import org.bouncycastle.crypto.signers.PSSSigner;
import org.bouncycastle.crypto.signers.RSADigestSigner;
import org.bouncycastle.crypto.signers.SM2Signer;
import org.bouncycastle.crypto.signers.X931Signer;
import org.bouncycastle.util.test.SimpleTest;

public class AsymmetricConstraintsTest
    extends SimpleTest
{
    public String getName()
    {
        return "AsymmetricConstraintsTest";
    }

    public void performTest()
        throws Exception
    {
        test1024bitDSA();
        test1024bitRSA();
        testEdwards();
        testEC();
        testDSA();
        testDH();
        testElgamal();
        testGost3410();
        testRSA();
        testRsaKEM();
        testECIESKEM();
        testSM2Cipher();
        testCramerShoup();
        testNaccacheStern();
    }

    private void test1024bitDSA()
    {
        BigInteger p = new BigInteger(
            "17801190547854226652823756245015999014523215636912067427327445031"
                + "444286578873702077061269525212346307956715678477846644997065077092072"
                + "785705000966838814403412974522117181850604723115003930107995935806739"
                + "534871706631980226201971496652413506094591370759495651467285569060679"
                + "4135837542707371727429551343320695239");
        BigInteger q = new BigInteger("864205495604807476120572616017955259175325408501");
        BigInteger g = new BigInteger(
            "17406820753240209518581198012352343653860449079456135097849583104"
                + "059995348845582314785159740894095072530779709491575949236830057425243"
                + "876103708447346718014887611810308304375498519098347260155049469132948"
                + "808339549231385000036164648264460849230407872181895999905649609776936"
                + "8017749273708962006689187956744210730");
        BigInteger x = new BigInteger("774290984479563168206130828532207106685994961942");
        BigInteger y = new BigInteger(
            "11413953692062257086993806233172330674938775529337393031977771373"
                + "129746946910914240113023221721777732136818444139744393157698465044933"
                + "013442758757568273862367115354816009554808091206304096963365266649829"
                + "966917085474283297375073085459703201287235180005340124397005934806133"
                + "1526243448471205166130497310892424132");

        DSAPublicKeyParameters pk = new DSAPublicKeyParameters(y, new DSAParameters(p, q, g));
        DSAPrivateKeyParameters sk = new DSAPrivateKeyParameters(x, new DSAParameters(p, q, g));

        CryptoServicesRegistrar.setServicesConstraints(new LegacyBitsOfSecurityConstraint(128));

        DSASigner signer = new DSASigner();

        try
        {
            signer.init(true, sk);
            fail("no exception");
        }
        catch (CryptoServiceConstraintsException e)
        {
            isEquals("service does not provide 128 bits of security only 80", e.getMessage());
        }

        // legacy usage allowed for verification.
        signer.init(false, pk);

        CryptoServicesRegistrar.setServicesConstraints(null);
    }

    private void test1024bitRSA()
    {
        BigInteger mod = new BigInteger("dbe3d9e35c7b3791e235e9146a5e27be06f202bbd2bc4c772e892b6d613da42cea1f0bffdd45220c1e7e9a21f94b0d86363986238e07d8b28fabde84ed35f1620daef807f27e021be84c7dffecc1106ab414a004a06c410f7cf96c720fbc70a2b357a4edd709ed23c7dc6e6e01433cd8a3e5b49b09ef4f4b6b0086f2fb07b4d9", 16);
        BigInteger pubExp = new BigInteger("10001", 16);
        BigInteger privExp = new BigInteger("2f06cbd29434c5edad335a65c359dfa604563dbf6d9257c8256bb09df3edfaeea02383ad74e514230362901433fc9927daf0f27f282105772ac2d71416a732b820163b22f7e808fa27af5d5e7952ba9f8ecd8e0724469a57bd0d3de828d4953aad0be5ed63ad5b726b012abf5540d4a766b6009124077aac577bcf2ef677531", 16);

        CryptoServicesRegistrar.setServicesConstraints(new LegacyBitsOfSecurityConstraint(112, 80));

        RSAKeyParameters pk = new RSAKeyParameters(false, mod, pubExp);
        RSAKeyParameters sk = new RSAKeyParameters(true, mod, privExp);
        RSAEngine rsaEngine = new RSAEngine();

        // signing - fail private key for encryption
        try
        {
            rsaEngine.init(true, sk);
            fail("no exception");
        }
        catch (CryptoServiceConstraintsException e)
        {
            isEquals("service does not provide 112 bits of security only 80", e.getMessage());
        }

        // legacy usage allowed for verification.
        rsaEngine.init(false, pk);

        // encryption - fail public key for encryption
        try
        {
            rsaEngine.init(true, pk);
            fail("no exception");
        }
        catch (CryptoServiceConstraintsException e)
        {
            isEquals("service does not provide 112 bits of security only 80", e.getMessage());
        }

        signer1024Test(pk, sk, new RSADigestSigner(SHA256Digest.newInstance()));
        signer1024Test(pk, sk, new PSSSigner(new RSAEngine(), SHA256Digest.newInstance(), 20));
        signer1024Test(pk, sk, new ISO9796d2PSSSigner(new RSAEngine(), SHA256Digest.newInstance(), 20));
        signer1024Test(pk, sk, new ISO9796d2Signer(new RSAEngine(), SHA256Digest.newInstance()));
        signer1024Test(pk, sk, new X931Signer(new RSAEngine(), SHA256Digest.newInstance()));
        signer1024Test(pk, sk, new GenericSigner(new RSAEngine(), SHA256Digest.newInstance()));

        // legacy usage allowed for decryption.
        rsaEngine.init(false, sk);

        CryptoServicesRegistrar.setServicesConstraints(null);
    }

    private void signer1024Test(RSAKeyParameters pk, RSAKeyParameters sk, Signer signer)
    {
        signer.init(false, pk);  // should be allowed (legacy)

        try
        {
            signer.init(true, sk);
            fail("no exception");
        }
        catch (CryptoServiceConstraintsException e)
        {
            isEquals("service does not provide 112 bits of security only 80", e.getMessage());
        }
    }

    private void testEdwards()
    {
        SecureRandom random = new SecureRandom();

        Ed25519KeyPairGenerator ed25519kpGen = new Ed25519KeyPairGenerator();
        ed25519kpGen.init(new Ed25519KeyGenerationParameters(random));

        Ed448KeyPairGenerator ed448kpGen = new Ed448KeyPairGenerator();
        ed448kpGen.init(new Ed448KeyGenerationParameters(random));

        X25519KeyPairGenerator x25519kpGen = new X25519KeyPairGenerator();
        x25519kpGen.init(new X25519KeyGenerationParameters(random));

        X448KeyPairGenerator x448kpGen = new X448KeyPairGenerator();
        x448kpGen.init(new X448KeyGenerationParameters(random));

        CryptoServicesRegistrar.setServicesConstraints(new LegacyBitsOfSecurityConstraint(256, 128));

        AsymmetricCipherKeyPair kp = ed25519kpGen.generateKeyPair();
        edwardsSignerTest(kp.getPublic(), kp.getPrivate(), new Ed25519Signer(), "128");
        edwardsSignerTest(kp.getPublic(), kp.getPrivate(), new Ed25519phSigner(new byte[1]), "128");
        edwardsSignerTest(kp.getPublic(), kp.getPrivate(), new Ed25519ctxSigner(new byte[1]), "128");

        kp = ed448kpGen.generateKeyPair();
        edwardsSignerTest(kp.getPublic(), kp.getPrivate(), new Ed448Signer(new byte[1]), "224");
        edwardsSignerTest(kp.getPublic(), kp.getPrivate(), new Ed448phSigner(new byte[1]), "224");


        kp = x25519kpGen.generateKeyPair();
        edwardsAgreementTest(kp.getPublic(), kp.getPrivate(), new X25519Agreement(), "128");
        edwardsAgreementTest(kp.getPublic(), kp.getPrivate(), new XDHBasicAgreement(), "128");
        edwardsAgreementTest(
            new XDHUPublicParameters(kp.getPublic(), kp.getPublic()),
            new XDHUPrivateParameters(kp.getPrivate(), kp.getPrivate()), new XDHUnifiedAgreement(new X25519Agreement()), "128");

        kp = x448kpGen.generateKeyPair();

        edwardsAgreementTest(kp.getPublic(), kp.getPrivate(), new X448Agreement(), "224");
        edwardsAgreementTest(kp.getPublic(), kp.getPrivate(), new XDHBasicAgreement(), "224");
//        edwardsAgreementTest(kp.getPublic(), kp.getPrivate(), new XDHUnifiedAgreement(new X448Agreement()), "224");

        try
        {
            ed25519kpGen.init(new Ed25519KeyGenerationParameters(random));
            fail("no exception");
        }
        catch (CryptoServiceConstraintsException e)
        {
            isEquals("service does not provide 256 bits of security only 128", e.getMessage());
        }

        try
        {
            ed448kpGen.init(new Ed448KeyGenerationParameters(random));
            fail("no exception");
        }
        catch (CryptoServiceConstraintsException e)
        {
            isEquals("service does not provide 256 bits of security only 224", e.getMessage());
        }

        try
        {
            x25519kpGen.init(new X25519KeyGenerationParameters(random));
            fail("no exception");
        }
        catch (CryptoServiceConstraintsException e)
        {
            isEquals(e.getMessage(), "service does not provide 256 bits of security only 128", e.getMessage());
        }

        try
        {
            x448kpGen.init(new X448KeyGenerationParameters(random));
            fail("no exception");
        }
        catch (CryptoServiceConstraintsException e)
        {
            isEquals(e.getMessage(), "service does not provide 256 bits of security only 224", e.getMessage());
        }

        CryptoServicesRegistrar.setServicesConstraints(null);
    }

    private void edwardsSignerTest(AsymmetricKeyParameter pk, AsymmetricKeyParameter sk, Signer signer, String sBits)
    {
        signer.init(false, pk);  // should be allowed (legacy)

        try
        {
            signer.init(true, sk);
            fail("no exception");
        }
        catch (CryptoServiceConstraintsException e)
        {
            isEquals("service does not provide 256 bits of security only " + sBits, e.getMessage());
        }
    }

    private void edwardsAgreementTest(CipherParameters pk, CipherParameters sk, RawAgreement agreement, String sBits)
    {
        try
        {
            agreement.init(sk);
            fail("no exception");
        }
        catch (CryptoServiceConstraintsException e)
        {
            isEquals("service does not provide 256 bits of security only " + sBits, e.getMessage());
        }
    }

    private void edwardsAgreementTest(AsymmetricKeyParameter pk, AsymmetricKeyParameter sk, XDHBasicAgreement agreement, String sBits)
    {
        try
        {
            agreement.init(sk);
            fail("no exception");
        }
        catch (CryptoServiceConstraintsException e)
        {
            isEquals("service does not provide 256 bits of security only " + sBits, e.getMessage());
        }
    }

    private void testEC()
    {
        SecureRandom random = new SecureRandom();
        ECKeyPairGenerator ecKp = new ECKeyPairGenerator();

        ecKp.init(new ECKeyGenerationParameters(new ECDomainParameters(X962NamedCurves.getByName("prime192v1")), random));

        CryptoServicesRegistrar.setServicesConstraints(new LegacyBitsOfSecurityConstraint(128, 80));

        AsymmetricCipherKeyPair kp = ecKp.generateKeyPair();

        // Note: some of these signers do not work with the passed in curve - the constraints test will trigger failure
        // first though.
        ecSignerTest(kp.getPublic(), kp.getPrivate(), new ECDSASigner());
        ecSignerTest(kp.getPublic(), kp.getPrivate(), new DSTU4145Signer());
        ecSignerTest(kp.getPublic(), kp.getPrivate(), new ECGOST3410Signer());
        ecSignerTest(kp.getPublic(), kp.getPrivate(), new SM2Signer());

        ecAgreementTest(kp.getPublic(), kp.getPrivate(), new ECDHBasicAgreement());
        ecAgreementTest(kp.getPublic(), kp.getPrivate(), new ECDHCBasicAgreement());
        ecAgreementTest(kp.getPublic(), kp.getPrivate(), new ECDHCStagedAgreement());
        ecAgreementTest(new ECDHUPublicParameters((ECPublicKeyParameters)kp.getPublic(), (ECPublicKeyParameters)kp.getPublic()), new ECDHUPrivateParameters((ECPrivateKeyParameters)kp.getPrivate(), (ECPrivateKeyParameters)kp.getPrivate()), new ECDHCUnifiedAgreement());
        ecAgreementTest(new MQVPublicParameters((ECPublicKeyParameters)kp.getPublic(), (ECPublicKeyParameters)kp.getPublic()), new MQVPrivateParameters((ECPrivateKeyParameters)kp.getPrivate(), (ECPrivateKeyParameters)kp.getPrivate()), new ECMQVBasicAgreement());
        ecAgreementTest(kp.getPublic(), kp.getPrivate(), new ECVKOAgreement(SHA256Digest.newInstance()));

        try
        {
            ecKp.init(new ECKeyGenerationParameters(new ECDomainParameters(X962NamedCurves.getByName("prime192v1")), random));
            fail("no exception");
        }
        catch (CryptoServiceConstraintsException e)
        {
            isEquals(e.getMessage(), "service does not provide 128 bits of security only 96", e.getMessage());
        }

        CryptoServicesRegistrar.setServicesConstraints(null);
    }

    private void ecSignerTest(AsymmetricKeyParameter pk, AsymmetricKeyParameter sk, DSA signer)
    {
        signer.init(false, pk);  // should be allowed (legacy)

        try
        {
            signer.init(true, sk);
            fail("no exception");
        }
        catch (CryptoServiceConstraintsException e)
        {
            isEquals("service does not provide 128 bits of security only 96", e.getMessage());
        }
    }

    private void ecAgreementTest(AsymmetricKeyParameter pk, AsymmetricKeyParameter sk, BasicAgreement agreement)
    {
        try
        {
            agreement.init(sk);
            fail("no exception");
        }
        catch (CryptoServiceConstraintsException e)
        {
            isEquals("service does not provide 128 bits of security only 96", e.getMessage());
        }
    }

    private void ecAgreementTest(MQVPublicParameters pk, MQVPrivateParameters sk, ECMQVBasicAgreement agreement)
    {
        try
        {
            agreement.init(sk);
            fail("no exception");
        }
        catch (CryptoServiceConstraintsException e)
        {
            isEquals("service does not provide 128 bits of security only 96", e.getMessage());
        }
    }

    private void ecAgreementTest(ECDHUPublicParameters pk, ECDHUPrivateParameters sk, ECDHCUnifiedAgreement agreement)
    {
        try
        {
            agreement.init(sk);
            fail("no exception");
        }
        catch (CryptoServiceConstraintsException e)
        {
            isEquals("service does not provide 128 bits of security only 96", e.getMessage());
        }
    }

    private void ecAgreementTest(AsymmetricKeyParameter pk, AsymmetricKeyParameter sk, ECVKOAgreement agreement)
    {
        try
        {
            agreement.init(new ParametersWithUKM(sk, new byte[32]));
            fail("no exception");
        }
        catch (CryptoServiceConstraintsException e)
        {
            isEquals("service does not provide 128 bits of security only 96", e.getMessage());
        }
    }

    private void ecSignerTest(AsymmetricKeyParameter pk, AsymmetricKeyParameter sk, Signer signer)
    {
        signer.init(false, pk);  // should be allowed (legacy)

        try
        {
            signer.init(true, sk);
            fail("no exception");
        }
        catch (CryptoServiceConstraintsException e)
        {
            isEquals("service does not provide 128 bits of security only 96", e.getMessage());
        }
    }

    private void testDSA()
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

        SecureRandom random = new SecureRandom();

        DSAKeyPairGenerator dsaKp = new DSAKeyPairGenerator();

        dsaKp.init(new DSAKeyGenerationParameters(random, dsaParams));

        CryptoServicesRegistrar.setServicesConstraints(new LegacyBitsOfSecurityConstraint(128, 80));

        AsymmetricCipherKeyPair kp = dsaKp.generateKeyPair();

        dsaSignerTest(kp.getPublic(), kp.getPrivate(), new DSASigner());

        CryptoServicesRegistrar.setServicesConstraints(new BitsOfSecurityConstraint(256));

        try
        {
            dsaKp.init(new DSAKeyGenerationParameters(random, dsaParams));
            fail("no exception");
        }
        catch (CryptoServiceConstraintsException e)
        {
            isEquals(e.getMessage(), "service does not provide 256 bits of security only 112", e.getMessage());
        }

        CryptoServicesRegistrar.setServicesConstraints(null);
    }

    private void dsaSignerTest(AsymmetricKeyParameter pk, AsymmetricKeyParameter sk, DSA signer)
    {
        signer.init(false, pk);  // should be allowed (legacy)

        try
        {
            signer.init(true, sk);
            fail("no exception");
        }
        catch (CryptoServiceConstraintsException e)
        {
            isEquals(e.getMessage(), "service does not provide 128 bits of security only 112", e.getMessage());
        }
    }

    private void testGost3410()
    {
        GOST3410Parameters gostParams = new GOST3410Parameters(
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

        SecureRandom random = new SecureRandom();

        GOST3410KeyPairGenerator gost3410 = new GOST3410KeyPairGenerator();

        gost3410.init(new GOST3410KeyGenerationParameters(random, gostParams));

        CryptoServicesRegistrar.setServicesConstraints(new LegacyBitsOfSecurityConstraint(128, 80));

        AsymmetricCipherKeyPair kp = gost3410.generateKeyPair();

        dsaSignerTest(kp.getPublic(), kp.getPrivate(), new GOST3410Signer());

        CryptoServicesRegistrar.setServicesConstraints(new BitsOfSecurityConstraint(256));

        try
        {
            gost3410.init(new GOST3410KeyGenerationParameters(random, gostParams));
            fail("no exception");
        }
        catch (CryptoServiceConstraintsException e)
        {
            isEquals(e.getMessage(), "service does not provide 256 bits of security only 112", e.getMessage());
        }

        CryptoServicesRegistrar.setServicesConstraints(null);
    }

    private void testDH()
    {
        SecureRandom random = new SecureRandom();

        DHKeyPairGenerator dhKp = new DHKeyPairGenerator();

        dhKp.init(new DHKeyGenerationParameters(random, DHStandardGroups.rfc2409_1024));

        CryptoServicesRegistrar.setServicesConstraints(new LegacyBitsOfSecurityConstraint(128, 112));

        AsymmetricCipherKeyPair kp = dhKp.generateKeyPair();

        dhTest(kp.getPublic(), kp.getPrivate(), new DHAgreement());
        dhTest(kp.getPublic(), kp.getPrivate(), new DHBasicAgreement());
        dhTest(new DHUPublicParameters((DHPublicKeyParameters)kp.getPublic(), (DHPublicKeyParameters)kp.getPublic()), new DHUPrivateParameters((DHPrivateKeyParameters)kp.getPrivate(), (DHPrivateKeyParameters)kp.getPrivate()), new DHUnifiedAgreement());
        dhTest(new DHMQVPublicParameters((DHPublicKeyParameters)kp.getPublic(), (DHPublicKeyParameters)kp.getPublic()), new DHMQVPrivateParameters((DHPrivateKeyParameters)kp.getPrivate(), (DHPrivateKeyParameters)kp.getPrivate()), new MQVBasicAgreement());

        try
        {
            dhKp.init(new DHKeyGenerationParameters(random, DHStandardGroups.rfc2409_768));
            fail("no exception");
        }
        catch (CryptoServiceConstraintsException e)
        {
            isEquals(e.getMessage(), "service does not provide 128 bits of security only 20", e.getMessage());
        }

        try
        {
            DHBasicKeyPairGenerator bKg = new DHBasicKeyPairGenerator();

            bKg.init(new DHKeyGenerationParameters(random, DHStandardGroups.rfc2409_768));
            fail("no exception");
        }
        catch (CryptoServiceConstraintsException e)
        {
            isEquals(e.getMessage(), "service does not provide 128 bits of security only 20", e.getMessage());
        }

        CryptoServicesRegistrar.setServicesConstraints(null);
    }

    private void dhTest(AsymmetricKeyParameter pk, AsymmetricKeyParameter sk, DHAgreement agreement)
    {
        try
        {
            agreement.init(sk);

            fail("no exception");
        }
        catch (CryptoServiceConstraintsException e)
        {
            isEquals(e.getMessage(), "service does not provide 128 bits of security only 80", e.getMessage());
        }
    }

    private void dhTest(AsymmetricKeyParameter pk, AsymmetricKeyParameter sk, BasicAgreement agreement)
    {
        try
        {
            agreement.init(sk);

            fail("no exception");
        }
        catch (CryptoServiceConstraintsException e)
        {
            isEquals(e.getMessage(), "service does not provide 128 bits of security only 80", e.getMessage());
        }
    }

    private void dhTest(CipherParameters pk, CipherParameters sk, MQVBasicAgreement agreement)
    {
        try
        {
            agreement.init(sk);

            fail("no exception");
        }
        catch (CryptoServiceConstraintsException e)
        {
            isEquals(e.getMessage(), "service does not provide 128 bits of security only 80", e.getMessage());
        }
    }

    private void dhTest(CipherParameters pk, CipherParameters sk, DHUnifiedAgreement agreement)
    {
        try
        {
            agreement.init(sk);

            fail("no exception");
        }
        catch (CryptoServiceConstraintsException e)
        {
            isEquals(e.getMessage(), "service does not provide 128 bits of security only 80", e.getMessage());
        }
    }

    private void testCramerShoup()
    {
        SecureRandom random = new SecureRandom();

        CramerShoupKeyPairGenerator kpGen = new CramerShoupKeyPairGenerator();
        CramerShoupParametersGenerator pGen = new CramerShoupParametersGenerator();

        pGen.init(1024, 1, random);

        kpGen.init(new CramerShoupKeyGenerationParameters(random,
                pGen.generateParameters(DHStandardGroups.rfc2409_1024)));

        CryptoServicesRegistrar.setServicesConstraints(new LegacyBitsOfSecurityConstraint(128, 80));

        AsymmetricCipherKeyPair kp = kpGen.generateKeyPair();

        CramerShoupCoreEngine csEngine = new CramerShoupCoreEngine();

        try
        {
            csEngine.init(true, kp.getPublic());
            fail("no exception");
        }
        catch (CryptoServiceConstraintsException e)
        {
            isEquals(e.getMessage(), "service does not provide 128 bits of security only 80", e.getMessage());
        }

        // will pass as decryption
        csEngine.init(false, kp.getPrivate());

        try
        {
            kpGen.init(new CramerShoupKeyGenerationParameters(random,
                    pGen.generateParameters(DHStandardGroups.rfc2409_1024)));
            fail("no exception");
        }
        catch (CryptoServiceConstraintsException e)
        {
            isEquals(e.getMessage(), "service does not provide 128 bits of security only 80", e.getMessage());
        }

        CryptoServicesRegistrar.setServicesConstraints(null);
    }
    private void testElgamal()
    {
        SecureRandom random = new SecureRandom();

        ElGamalKeyPairGenerator eKpg = new ElGamalKeyPairGenerator();

        eKpg.init(new ElGamalKeyGenerationParameters(random,
            new ElGamalParameters(DHStandardGroups.rfc2409_1024.getP(), DHStandardGroups.rfc2409_1024.getG())));

        CryptoServicesRegistrar.setServicesConstraints(new LegacyBitsOfSecurityConstraint(128, 80));

        AsymmetricCipherKeyPair kp = eKpg.generateKeyPair();

        ElGamalEngine eEngine = new ElGamalEngine();

        try
        {
            eEngine.init(true, kp.getPublic());
            fail("no exception");
        }
        catch (CryptoServiceConstraintsException e)
        {
            isEquals(e.getMessage(), "service does not provide 128 bits of security only 80", e.getMessage());
        }

        // will pass as decryption
        eEngine.init(false, kp.getPrivate());

        try
        {
            eKpg.init(new ElGamalKeyGenerationParameters(random,
                new ElGamalParameters(DHStandardGroups.rfc2409_1024.getP(), DHStandardGroups.rfc2409_1024.getG())));
            fail("no exception");
        }
        catch (CryptoServiceConstraintsException e)
        {
            isEquals(e.getMessage(), "service does not provide 128 bits of security only 80", e.getMessage());
        }

        CryptoServicesRegistrar.setServicesConstraints(null);
    }

    private void testRSA()
    {
        SecureRandom random = new SecureRandom();

        RSAKeyPairGenerator rsaKpg = new RSAKeyPairGenerator();

        rsaKpg.init(new RSAKeyGenerationParameters(BigInteger.valueOf(0x10001), random, 1024, 100));

        CryptoServicesRegistrar.setServicesConstraints(new LegacyBitsOfSecurityConstraint(128, 80));

        AsymmetricCipherKeyPair kp = rsaKpg.generateKeyPair();

        RSAEngine rsaEngine = new RSAEngine();

        try
        {
            rsaEngine.init(true, kp.getPublic());
            fail("no exception");
        }
        catch (CryptoServiceConstraintsException e)
        {
            isEquals(e.getMessage(), "service does not provide 128 bits of security only 80", e.getMessage());
        }

        // will pass as decryption
        rsaEngine.init(false, kp.getPrivate());

        try
        {
            rsaKpg.init(new RSAKeyGenerationParameters(BigInteger.valueOf(0x10001), random, 1024, 100));
            fail("no exception");
        }
        catch (CryptoServiceConstraintsException e)
        {
            isEquals(e.getMessage(), "service does not provide 128 bits of security only 80", e.getMessage());
        }

        CryptoServicesRegistrar.setServicesConstraints(null);
    }

    private void testRsaKEM()
    {
        SecureRandom random = new SecureRandom();

        RSAKeyPairGenerator rsaKpg = new RSAKeyPairGenerator();

        rsaKpg.init(new RSAKeyGenerationParameters(BigInteger.valueOf(0x10001), random, 1024, 100));

        CryptoServicesRegistrar.setServicesConstraints(new LegacyBitsOfSecurityConstraint(128, 80));

        AsymmetricCipherKeyPair kp = rsaKpg.generateKeyPair();

        KDF2BytesGenerator kdf = new KDF2BytesGenerator(new SHA1Digest());
        SecureRandom rnd = new SecureRandom();
        RSAKEMGenerator rsaKem = new RSAKEMGenerator(128 / 8, kdf, rnd);

        try
        {
            rsaKem.generateEncapsulated(kp.getPublic());
            fail("no exception");
        }
        catch (CryptoServiceConstraintsException e)
        {
            isEquals(e.getMessage(), "service does not provide 128 bits of security only 80", e.getMessage());
        }

        // will pass as decryption
        RSAKEMExtractor rsaExt = new RSAKEMExtractor((RSAKeyParameters)kp.getPrivate(), 128 / 8, kdf);

        try
        {
            rsaKpg.init(new RSAKeyGenerationParameters(BigInteger.valueOf(0x10001), random, 1024, 100));
            fail("no exception");
        }
        catch (CryptoServiceConstraintsException e)
        {
            isEquals(e.getMessage(), "service does not provide 128 bits of security only 80", e.getMessage());
        }

        CryptoServicesRegistrar.setServicesConstraints(null);
    }

    private void testECIESKEM()
    {
        SecureRandom random = new SecureRandom();
        KDF2BytesGenerator kdf = new KDF2BytesGenerator(new SHA1Digest());

        ECKeyPairGenerator ecKp = new ECKeyPairGenerator();

        ecKp.init(new ECKeyGenerationParameters(new ECDomainParameters(X962NamedCurves.getByName("prime192v1")), random));
        AsymmetricCipherKeyPair kp = ecKp.generateKeyPair();

        byte[] out = new byte[49];
//        ECIESKeyEncapsulation kem = new ECIESKeyEncapsulation(kdf, random);
//
//        kem.init(kp.getPublic());
//        KeyParameter key1 = (KeyParameter)kem.encrypt(out, 128);
//
//        CryptoServicesRegistrar.setServicesConstraints(new LegacyBitsOfSecurityConstraint(128, 80));
//
//
//        ECIESKeyEncapsulation eciesKEM = new ECIESKeyEncapsulation(kdf, random);
//
//        try
//        {
//            eciesKEM.init(kp.getPublic());
//
//            eciesKEM.encrypt(new byte[0], 128);
//            fail("no exception");
//        }
//        catch (CryptoServiceConstraintsException e)
//        {
//            isEquals(e.getMessage(), "service does not provide 128 bits of security only 96", e.getMessage());
//        }
//
//        // will pass as decryption
//        eciesKEM.init(kp.getPrivate());
//
//        eciesKEM.decrypt(out, 128);

        CryptoServicesRegistrar.setServicesConstraints(null);
    }



    private void testSM2Cipher()
    {
        SecureRandom random = new SecureRandom();
        ECKeyPairGenerator kpGen = new ECKeyPairGenerator();

        kpGen.init(new ECKeyGenerationParameters(new ECDomainParameters(ECNamedCurveTable.getByName("P-256")), random));

        AsymmetricCipherKeyPair kp = kpGen.generateKeyPair();

        CryptoServicesRegistrar.setServicesConstraints(new LegacyBitsOfSecurityConstraint(256, 128));
        SM2Engine engine = new SM2Engine();
        try
        {
            engine.init(true, new ParametersWithRandom(kp.getPublic(), random));
            fail("no exception!");
        }
        catch (CryptoServiceConstraintsException e)
        {
            isEquals(e.getMessage(), "service does not provide 256 bits of security only 128", e.getMessage());
        }

        // decryption should be okay
        engine.init(false, kp.getPrivate());

        CryptoServicesRegistrar.setServicesConstraints(null);
    }

    private void testNaccacheStern()
    {
        SecureRandom random = new SecureRandom();

        NaccacheSternKeyPairGenerator kpGen = new NaccacheSternKeyPairGenerator();

        kpGen.init(new NaccacheSternKeyGenerationParameters(random, 1024, 8, 40));

        CryptoServicesRegistrar.setServicesConstraints(new LegacyBitsOfSecurityConstraint(128, 80));

        AsymmetricCipherKeyPair kp = kpGen.generateKeyPair();

        NaccacheSternEngine nsEngine = new NaccacheSternEngine();

        try
        {
            nsEngine.init(true, kp.getPublic());
            fail("no exception");
        }
        catch (CryptoServiceConstraintsException e)
        {
            isEquals(e.getMessage(), "service does not provide 128 bits of security only 80", e.getMessage());
        }

        // will pass as decryption
        nsEngine.init(false, kp.getPrivate());

        try
        {
            kpGen.init(new NaccacheSternKeyGenerationParameters(random, 1024, 8, 40));
            fail("no exception");
        }
        catch (CryptoServiceConstraintsException e)
        {
            isEquals(e.getMessage(), "service does not provide 128 bits of security only 80", e.getMessage());
        }

        CryptoServicesRegistrar.setServicesConstraints(null);
    }

    public static void main(
        String[] args)
    {
        runTest(new AsymmetricConstraintsTest());
    }
}
