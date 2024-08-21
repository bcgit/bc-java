package org.bouncycastle.pqc.jcajce.provider.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import junit.framework.TestCase;
import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jcajce.interfaces.MLDSAKey;
import org.bouncycastle.jcajce.interfaces.MLDSAPrivateKey;
import org.bouncycastle.jcajce.spec.MLDSAParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;

/**
 * MLDSA now in BC provider
 */
public class MLDSATest
    extends TestCase
{
    byte[] msg = Strings.toByteArray("Hello World!");

    public void setUp()
    {
        if (Security.getProvider(BouncyCastlePQCProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new BouncyCastlePQCProvider());
        }
        Security.addProvider(new BouncyCastleProvider());
    }

    public void testPrivateKeyRecovery()
            throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-DSA", "BC");

        kpg.initialize(MLDSAParameterSpec.ml_dsa_65, new MLDSATest.RiggedRandom());

        KeyPair kp = kpg.generateKeyPair();

        KeyFactory kFact = KeyFactory.getInstance("ML-DSA", "BC");

        MLDSAKey privKey = (MLDSAKey)kFact.generatePrivate(new PKCS8EncodedKeySpec(kp.getPrivate().getEncoded()));

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ObjectOutputStream oOut = new ObjectOutputStream(bOut);

        oOut.writeObject(privKey);

        oOut.close();

        ObjectInputStream oIn = new ObjectInputStream(new ByteArrayInputStream(bOut.toByteArray()));

        MLDSAKey privKey2 = (MLDSAKey)oIn.readObject();

        assertEquals(privKey, privKey2);

        assertEquals(kp.getPublic(), ((MLDSAPrivateKey)privKey2).getPublicKey());
        assertEquals(((MLDSAPrivateKey)privKey).getPublicKey(), ((MLDSAPrivateKey)privKey2).getPublicKey());
    }

    public void testPublicKeyRecovery()
            throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-DSA", "BC");

        kpg.initialize(MLDSAParameterSpec.ml_dsa_87, new MLDSATest.RiggedRandom());

        KeyPair kp = kpg.generateKeyPair();

        KeyFactory kFact = KeyFactory.getInstance("ML-DSA", "BC");

        MLDSAKey pubKey = (MLDSAKey)kFact.generatePublic(new X509EncodedKeySpec(kp.getPublic().getEncoded()));

        assertEquals(kp.getPublic().hashCode(), pubKey.hashCode());

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ObjectOutputStream oOut = new ObjectOutputStream(bOut);

        oOut.writeObject(pubKey);

        oOut.close();

        ObjectInputStream oIn = new ObjectInputStream(new ByteArrayInputStream(bOut.toByteArray()));

        MLDSAKey pubKey2 = (MLDSAKey)oIn.readObject();

        assertEquals(pubKey, pubKey2);
        assertEquals(pubKey.hashCode(), pubKey2.hashCode());
    }

    public void testRestrictedSignature()
            throws Exception
    {
        doTestRestrictedSignature("ML-DSA-44", MLDSAParameterSpec.ml_dsa_44, MLDSAParameterSpec.ml_dsa_87);
        doTestRestrictedSignature("ML-DSA-65", MLDSAParameterSpec.ml_dsa_65, MLDSAParameterSpec.ml_dsa_87);
        doTestRestrictedSignature("ML-DSA-87", MLDSAParameterSpec.ml_dsa_87, MLDSAParameterSpec.ml_dsa_44);
    }

    private void doTestRestrictedSignature(String sigName, MLDSAParameterSpec spec, MLDSAParameterSpec altSpec)
            throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-DSA", "BC");

        kpg.initialize(spec, new SecureRandom());

        KeyPair kp = kpg.generateKeyPair();

        Signature sig = Signature.getInstance(sigName, "BC");

        sig.initSign(kp.getPrivate(), new SecureRandom());

        sig.update(msg, 0, msg.length);

        byte[] s = sig.sign();

        sig = Signature.getInstance(sigName, "BC");

        assertEquals(sigName, sig.getAlgorithm());

        sig.initVerify(kp.getPublic());

        sig.update(msg, 0, msg.length);

        assertTrue(sig.verify(s));

        kpg = KeyPairGenerator.getInstance("ML-DSA", "BC");

        kpg.initialize(altSpec, new SecureRandom());

        kp = kpg.generateKeyPair();

        try
        {
            sig.initVerify(kp.getPublic());
            fail("no exception");
        }
        catch (InvalidKeyException e)
        {
            assertEquals("signature configured for " + spec.getName(), e.getMessage());
        }
    }

    public void testRestrictedKeyPairGen()
            throws Exception
    {
        doTestRestrictedKeyPairGen(MLDSAParameterSpec.ml_dsa_44, MLDSAParameterSpec.ml_dsa_87);
        doTestRestrictedKeyPairGen(MLDSAParameterSpec.ml_dsa_65, MLDSAParameterSpec.ml_dsa_87);
        doTestRestrictedKeyPairGen(MLDSAParameterSpec.ml_dsa_87, MLDSAParameterSpec.ml_dsa_44);
    }

    private void doTestRestrictedKeyPairGen(MLDSAParameterSpec spec, MLDSAParameterSpec altSpec)
            throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(spec.getName(), "BC");

        kpg.initialize(spec, new SecureRandom());

        KeyPair kp = kpg.generateKeyPair();

        assertEquals(spec.getName(), kpg.getAlgorithm());
        assertEquals(spec.getName(), kp.getPublic().getAlgorithm());
        assertEquals(spec.getName(), kp.getPrivate().getAlgorithm());

        kpg = KeyPairGenerator.getInstance(spec.getName(), "BC");

        try
        {
            kpg.initialize(altSpec, new SecureRandom());
            fail("no exception");
        }
        catch (InvalidAlgorithmParameterException e)
        {
            assertEquals("key pair generator locked to " + spec.getName(), e.getMessage());
        }
    }

    public void testMLDSARandomSig()
            throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-DSA", "BC");

        kpg.initialize(MLDSAParameterSpec.ml_dsa_44, new SecureRandom());

        KeyPair kp = kpg.generateKeyPair();

        Signature sig = Signature.getInstance("ML-DSA", "BC");

        sig.initSign(kp.getPrivate(), new SecureRandom());

        sig.update(msg, 0, msg.length);

        byte[] s = sig.sign();

        sig = Signature.getInstance("ML-DSA", "BC");

        sig.initVerify(kp.getPublic());

        sig.update(msg, 0, msg.length);

        assertTrue(sig.verify(s));
    }

    public void testMLDSAKATSig()
            throws Exception
    {
        byte[] pubK = Hex.decode("dc7bc9a2e0b6dc66823ae4fbde971c0cfc46f9d96bbfbeebb3470ae0a5a0139fdd6a6ce5bc76e94faa9e9250abd4cee02cf1ee46a8e99ce12d7395781fa7519021273da3365519724efbe279add6c35f92c9d42b032832f1bf29ebbecd3ec87a3af3da33c611f7f35fa35acab174024f118979e23bf2fe069269a2ec45fbc1b9c1fb0e1f05486a6a833eb48adc2960641d9af6eb8b7381b1ec55d889f26b084ddfa1c9ed9b962d342694cede83825309d9db6bd6ba7582132534861e44a04388a694242411761d34e7c085d282b723c65948a2ac764d9702bd8ed7fe9931d7d8704a39e6508844f3f84843c305594fe6e5404e08f18ed039ac6563cbaa34b0ca38320299d6256ec0f78d421f088159d49dc439cbc539a55884a3eb4efc9cf190b42f713441cb97004245d41437a39b7b77fc602fbbfd619a42363714b265173cae68fd8a1b3ca2bd30ae60c53e5604577a4a3b1f1506e697c37432dbd883553aac8d382a3d250cf5b29e4d1be2cbcd531ff0e07e89c1f7dbc8d4529aeebe55b5ce4d0214bfdec69e080bd3ef36cca6a54933f1ef2f37867c0d38fd5865b87929115808c7e2595458e993bacc6c5a3b9f5025001e9b41447708bfbaa0462efa63876c42f769908b432f5485508a393224960551d77eadfaf4411cbc49fdff46f2f155ddd6ec30867905b709888ca0f30f935fb8d7f4803cfc7a5f7790ca181d99ca21f2621d69a5c6d49c76b4969da62740a378470332b30947ab31ccdb9ba0c7b625879eec4bd81f0200ba23504a7dc3b118bc2ab1145df13af3c8cc39f577873b84911b3d85fbbf4cb19e4d36b10a938eeb78b599dc86615fd6cec6eb7b8f7afa5f6d6be19ea81630d36ccfb2f487de50d0cf46da8d3fe3512812043c0e3ef2d7231fb0b0a35a0fb283be30a1247780f30ae0294e8b6f5897383edb895595f577524df54593cdf927b4967616ee3913e4d6b29b0dbd7c33a2a45e4ef1b1954ea5d91ce37efc1302e7ce02a97395565da2a5c5d3fdb0d87684e9b1c0ad07ec33df2dfad528e2ea0966d2a47dd5ee88e77d653c0d004fab0165f0757c4da40af327e7192536c79947a80a827aa2107dacfae3debfc8fad3d6e08076d938c510a276bdf6721a1f087cb169515028ad5ce27a1047abd92809934ca63b893f71f9a34a99c0fd30310c47e9aa37394d0ab73b254d3ca69d9c5549c9479aae24264ac5ea64d3fd821c3962ec77e709f9d30bc7b65a52e48c16e80603558caca1811411c3155d1f949fc9cf9aa9385a7199e99be77a66fad7eed91258de55b2c4c83f9a050adebea5f09758f40dac4a1c394ee8d687879150d26426895ab1938e14ae11b376254c91fc6130436996f8ed43bd27be20ec9067111c116ec94cc2b06cc91a13c5d10bbd7eecea4792f17b2b77631ef145e9fb41a83eaa11c2b72a48fb90fdbd88644c4edf8ab20dce3118364b276ac1237b36c8926e346aab5a111aa0bf341c518b7bff9e9dbb8bcb4728601b3760663e67650331e6fb54ac82fc414cb8ddfc160a25311ec5272de46217fef8b992ff89754fbee351f21bb90b6c97078b510c983350681266c8fed1f0583c5151e7b8fe3b7292319699687cc6b641fdbd689428543bc0fa1facc109de65b62784c2d985ab15d77d3af12af6d03e8d1859a553688584d75ef673a1de74093ee108c761fff32c217c231b0e2953daf521429264c0963bc8a5cdeddc617a7285b934ea51ddb5cdab23bcede86be36e001bc65c65e9a1c94baff4fab8eb5f8ed42ec377423633fe00049142467c47c5d58a7202c8e9104841c1f7f380145a6a0a828c570235e507ae5868a6062f722bb98ff6be");
        byte[] privK = Hex.decode("dc7bc9a2e0b6dc66823ae4fbde971c0cfc46f9d96bbfbeebb3470ae0a5a0139ff037b84e75537e0a1cf02a517acfe323ffffe11df72e4f38430e0e66a2654b2f2ef757da47649d9f63fa03f1bf6fe6bc7c62971a98a2bd9d36eb0ec43ad4e9d940df3bb5874f5c92192aa31e0535d3cf70950bba858d11a688eaf854f63ecfc520c50d624891434265d8b0680c03061040299a104082c0910c8508d1100d44a6509408292211125b90508a2688e1302dc4021280028ac302611820851237808a000ae2040421b4910bb80550a08051b2511c28428a3672a494504910201bb45161424424a75001328181942d62a850023449ca94200b296213156408924c48122100b605030208e0060200a311e1802021116483a62898029291480801083041066613200e5b360951400c53000aa08851944842e316704ab2089b92440025121b0309418209c2a0800b290a819851c4340da4424500a0105b048e603400138928a4422648002c90202d194068e2146d19278a083746e4146914006422c660d3a03013242844965014166da0284dcc462e94367100232e1c114909a2040131060a2172c2142ada000c5a260d13228a62c444e3142d013445980224d33841c0308121a621e348720b1984d2c89108b8690887714a2884d496451a9301ca2285da30859ac851dcc00820106060465262302aa224251044640b2842988011540692144251d236719bb4900b082890188e41c469e1a469032160e01409d3020c20c88c1cb23164086218476920228ccb8470089528029550533270013405888424541041d202881aa84ccac88181008d0392899ab809d9900c9a1290614065c9322d89860c123521cc4266c8360010062411028ea3b44d44023043a0285a002ed1980c4882658922441c010212907084226e12134d011902519064113364c91806c2c04589262908b63024308cda022e0c27250b367058162c5116420b4946c1208841246c99466a04434e18a86c821661922028639409c30211029520211782d43868003460c84688e0160000a32dc0a82824b640831464c81022a2086503234ac8122ea098418c2072cc308a62c665093408412682da429089328514967081226001176d5948428ab88d592051d80892e2c0889044700ac0245a020904218a59c45094441094140820460209270c441020dcc8209212015038250c456e4a1666223770dc808ca426412222441ba3618a343099844099c42952046d88146ccb242a7cd129a8d333115c62d033b6a8357cf7cd10268ab12f16fceb7975d0a28a6c4822213c9a772df084ad91a669e2040550fc5e8d0aeb10fab2375fc9625ef9cd48c19631997a1cb6455d2c6286c569c9637add0317ce990996b28e51c3f3f717fb5907bbdd53961ad3497f2c3c473cce170906ac4c624a89aa8fbe624d99385e9c9548bf05e8cafd47d2476e41b73001f813726499e88b2b3b6f596ca311657850346598994c40e34747161e4e76264deef2a3019389d1594c942301af47b7544c23ecda2df2dece81e487d8f3f58ea89cd811d7275807ff1b0369ba86470088c174a3099fdafbe5fbb4d158801053b2b435d54059e26dee76d10a7a372f06b0b88b985b32f52052387438be8dc8bc6ae7369e2da9aa5e2585f8de403d091ccb7f790d54ddb34c608b0876f2825e9113be20a2b85867a01bda53287ac780bcd8b606d2e6d7712c56ce0142d22fe6b786de544963e134fecedfafb83d763061d799096a59e30d4472e440ae1faaabdf42640ce69740ceb9cae1a9612c21931b74af3f780236123321b205b6efd6cbb134f4c73d63c0c13e660b59d5920bc33197c355853d8d1cddc7959f7bc500ac81d985016f5b89a0eec79b0d9364ead8e38577c2a6549f2d067cb09438fdb21220aec80f6e22a476f332a2a4a0b7acbeb9e078d2b5a92ae84c924f7cb19fc7df377beb6546af97aa985c747cd111a127a674b4c26d89c14485b82e3a498a12d05406febd6c4d4b8bc051ab2cb91224b078538374b794b7dd9ddf3ac2b4a671fb7b9cf5acb78622ae2709eb2db16943aa24a9c97a81077bc784d25c0ea5991d2de883798a1f0e78f3361ed6a10dded81b1d683658331534fd7c01bc0eb00dfc4c3c84f0693046ff806bb200dd7bd4c0e6abca3f2934b4814fc0e1f8be615a2dda7c8a8d06cf9ce8566b40f4a6543b25bacddc926863fc0fa2007d6d7bf6d18dc98df696bd0865bf0be4c492b8043a32def8e3595ba7da345252f38f95be10fd7fb899b498fa01b09de5d5608eabc44a721aa04c4ef1dcb86102ac5f5f79c9708dcf5c5e896edd8c2c7bde3fa83e6ffce22d66174e31657a0b6361585e669d3031952f08631ae1f16ff90b90d0aad3c6d7e1dd0a9c41ab00a6e1c4f96af9ac5b79fcf821ffc016cb059245fb78dbe6c633d965aaab5333be07195c4b74b18e4600ce783c0a914ef4281016e80a7c9aa92d0fd789879c5e6751125ecb154432311e41cebd4fab3a31e4d2ce22d0f8c67737bf8a0dd85fe1349d5079a4d5feb3fee9378ca47ae46cc58a3f02038cfd53c4cee9cc4270cebc3d115a39c831e8ed41c4dbe4051b51d7872ba0c2bb163e0085201188eaa624a6bea9400a3a1fcc355a57f15704e61fda55a5dbaea8448fa5cb2d377a07f58305ad107e844ab4806e5bf99c1f513ee1d0a2acc04549f0801742169a77971d0adbfbfe0dd2ee5d16bc461e35748d1f3f6f4598321e8c49e79e740f990359858d2729dde007fcb26fdda9aa6e2ec4bd736f2836e7e4c83440191c849f6a53c72a4f8f830d001ea3b18f3cb4a5bd3cf066032b4932cfd2e62a9b55723fa61c688c935518af6860cd649bfbf1bf5fdc1f36dcaefaa157438d1cc8d56a150161511df82631f5e88e773e4ce263f276b7b3678d4c6fc75311d411c0d01bfdb595bb70552838e1b86517c837d909e772b428599e1fe569f77ce61531fde6fd31cdce1bdee4ba467fcbfbb9feeaad99fef67d4906e036c73662ddce158d4e5d4635e5d366f79f31a19d1b3dc4a591b0df194bb06c18147f41d88d1a409becdfb67eb063d16312266fd51b521ba9115e2e5e2aeae6ec511cede13ed4132ffbe0273f6c7039b3874f058804a54809af60557a21d9b4b831d04156a7c22dcbcdfe14f62437f449cb5ef12bf4251d485496cd835c0c2bc58bd845963dfa76ecd68519c4bdaf110be7ab052876dc3407591568c956ea3bf107c90fd5853a292f59a8d4b58b5d3fddf29bdbeac36852e3c69766fe460176a801831292b8e88a74a01ecbbe09a7b4d74cfd7fd628841944d9d556dbd60c76f96f07dc53443805ee9aa09365de4fb8179252c6b099b5dd351fdefc23dbd8090596c5d208ffd2c5661d8e5612dd574fc69045c769a969e600d77cfe192f1d3ae911289355c585811491b0ccd73692ab158824ab9edf8ac8193f0b33e6138b72c6dcd5d344f807b3da92425037de5ea4eead1c795effaa145e2ecdd327606eb2609929b9474b2bb04653602555c068385e92f06f29ca613ce5b4404f01ab1805db0acaa890330d291f40692df382509302b6dc8668f2c8f2d3a44fd58dca26e9802794f73d25b3149e6d576441");
        byte[] msg = Hex.decode("D81C4D8D734FCBFBEADE3D3F8A039FAA2A2C9957E835AD55B22E75BF57BB556AC8");
        byte[] s = Hex.decode("fcc4f40c043066771043d494eb13181802151a8f82c5c4e29582f6b0fa35023fa7042b68c6630fd99b8152265f4e439ff2430197e57d4195f3bdb6e92e707f964006001f748b94ed0249414226b5f439ab4daa261f9b549f40fd2c690521a5934230c808899473ce5abb67f406a020db59ead7c5eac5c53156a4bb603603b46db9c2fa5f5bf26fbb67c3a98a399ef245d30d761a1adda9d4439d1d1ce86480c2b123e984209fcc830a300b1c8108e320d34a27a752b2d0cec268de0f9f9eee7f4c7cca6f64d8a0288f6c92699cded9cacca31d80e6bb5107af87d1021fc6787d79f001e04a4aabfbaef2b172c5010e6389ab8075496f50558fba91c70e6440640f522b6a38bbe429cfd5352031eb651721823a3705514b6aebb9c3954f79fd01cb228d731d7a41b462cc1a1c855905ff17f14d7f8b71d0f17c03e4239d2881012f94466fcd1e66e62227d6812f8b81157b8954a671391c064838cb215c79fc6fc9d85ef0c891aea9e9ab16500cf06613a02ca82d25decfdbd1a81090b280b4e3213a5db5f7020d30d8169ea176975f72d1910c64684afc2516a35ec35308c4d127fd5c9f54786d2f7ff60c6110514d6bd7720507ec9ede750e4b9929b20ffa65dd714eb11e4e0865c3d2930d8170018e9eb29b72b1e66b7a65afae1617d752ea435f88db7f87dbd29e9859957eb73b766c38675e96d1be9c4404297e6e40b5009fa9adde177980d25bf3b76c130682f8105c1257bd20b9624b09157d2f6ed42dd9b080903603786a0ec3a0d8a847999eb4788f23f1a95db1f5818dadcbad60078a8b1be01d02ac3ee9ba88cf5909a4d4318d9fd2a439aa37e8da68f6208dc5ec3cd659a5aaa3362ad0ff4a3ba6ed5ea75cb710c83bda0afbc14ae4a61e19a0ab4e9597bcfdb9da986308322cd7f534b173f76e0151e693b52bd2029a7ea294bad8ced7ca0485e58c73a71eb5ddc1bfa12f2a0026aec90db969e6cea486e6628903e75275a39a1105aad7abe683660e02b6fc12bd59227358bc20a49eec69b4c03318c90bb3d9725ac1fe6f9609349b14eea21ea996cb118258035213a8fab19339cea94043667cf2ee596c3fb01d136d40450adbf9761d047e6897b975d291a53097b747bc9d6342e91b88bd0a2e7d6444973557ffae72123d84b228131951dda7a10f993f2427a9a9dc822d822363c9517dca0bfffa2f6aa66e3fe5802c05026b72c03813ef26a90855565d419d402ad1b3b1719c2d23637c425eb1cfaa6e5bb82c87735b802ffb1fdd6693385af5f96a73a8e482e9128f428571edd73c1495be9ffb2a6b5a28a1b8a30ec737f82989e328433255e53cb901764f0c0341cb67e5c6275fee34e35c3e6057cc1af790bb111b5a7a2f86de7c680f42d838ac4e8059677c9d382f167af649253f31c00120e797ec93d0a31af80b44ad2fbf0a8a1f67d1a63ee448d85442677f24c60d581555fb6c693bf8829e5062f4b3a66f028c7505600464138d4c026100e55d878434aba2d41d0e90d4dda9e2bd46c337efce479f999cb50adc080575ecebfd1ce6ad6450f9d7ec025c793493e8c11059d3fae194476efd16742fa2d1a399d6cdffc0a6cf1e4e13ec0f515c21846b9da843f2b0af70de17f7bcbc11a2f11e9cb1efa24a28477c0fc5ea4f6a644e608c028e5aab8f82109a07ce8a06e99012593f32051d865f561cfb365312ef49338ceeeb3842ce1ee2381a1641043c32c852a1add433075ddb94863749b3c7dc6ac10e681293deba2a355843a1ead7448f2af81beb5500357a81a5375355941ea2172c96e1cfb84120f93496943d344af409a8573bbf5961d1dd044bc2ce21ad2b7c5c721b324d697e786e711a8c08d358f52b96507b6d380048e4783740ff996610aa6a2b5e6788d68b065717b507bcb2df05e0af6268735bd5e929798ac5e0f12fdab6da267dab9102c6ae20451e644499c2c8408eeeac9abc7130dee6c33144819ef78905b45dbb9fef7ebc92871092a8aebaf9c754544b055fbdc52b760687b15b22d3582e3d881c5afc00b360f504c67fc90ccdb1ee8d8626f7f12596fdf9ba95621bd00a5f6331261da4340d5bc5a4cc222f60d9e220f6e1b56d1492b20d68b75d7cef20df2737821980efca83822f19cb4f5ece26665e6b07c43b65715df26632534e84d7b3d109a5fb026052bc9323a02a41a5d194ef0990713a578219b989b9a5383cb64e4cdd8ab3ca7807895272490b3cf72a01ae21615bf6af12f2283cc1cc400ed660bba87dfe9bc1e26c29c50ff3a01a14f83b52d20116f8b7b3b133810476a38c588d36f85c5c9def402b13e89201aacdacdf2c6ea8cc0e819423e86f080d6690a136ac4879c26e9a45c80a0d5d77d7ec4f0e395ac5bfb0b67d6ba617fff4f3f0bdbf50a383827db69a405590ad8bd752f55ef299800e1a5eeca7dec712b4343cd82ed6cd96c60fa0c65a960105d3717d3391ac116c868202c11b11ef2cdb2e8a3f3df1940c8f98c372c6d9989044b922f48b38e97168ce900a5af99bd9a81cd1e26109bf5de678e5c1d42b8fd29a738ee2125aca3ca9f5dc18a0e36a16bd64c04c498667e95fbc582affcdbc4ef896fcc1971352e2195d235321f750bb5ebb44bc3c411f7129518780dee0fb706ed16cc749753b8ee44ca7008a6922ab90c803002260f6f5c605436306d96c9b7c538a19cef0d35479d1dd5e5874e3b1a2ff4c1b50b942c3f166d7d9e51f870faba93a2ddf2b32b21f7552606af24772b428cf47d473f8a5cd2fab4c1bdbcbcc9abb6d017e2f0f3f18e224c4f3b1f0384021dd8d58e8b62c1f2011cf17343b0cf86774fc8b85882fbfc6e884cfc97bafb90d6381a647aef10dbcfe263863311fb30d91d885b049d41050f461b08de163cbb1b49ae1b4bcd64175bb3b96b154cd2946dd2961b629bd13beda7867c93b31242aaad973db6f92093880461a43071a62b361cff82bae2f32be33f1e36062f8f7ab7fb3c50c8c5ea6d7e0fb023ab994c45e8b43bcc6ace4e7b0529a41842b64aabf0cfa30c5d98f7897ace3074dd75f0f61f228d911def6258b3b3e95487d301ebdd9c80fe323e7929897784c04da3b52c5ff6fee1f28e309bede2ca244af7a30ae146137f472cff9ecfc2d1fb7e20f9108a6c8bcec4cbb877f3fa15820e5e21596949dd4b2d659f3e450d6f5e715cb307da9af905af6f695b519f5af28e2c3bc4c7633f1191486be9969746cc8c0b70405d9c7f77f8cadc2cacd9c492b774902cf9ced338fe612909795ae6c951258faa52b5f5a363ddedf5a10a4d4e8e253242b626f7ec8d5eff9050a393b3e44494b748397afb6cbccd4f8f9fa364955787a878a96a5acc0c6cbd9eaf6123242446e96a8b7c0d7dff1000000000000000000000000000000000000000000000000091c2c38");

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-DSA", "BC");
        SecureRandom katRandom = new NISTSecureRandom(Hex.decode("061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1"), null);

        kpg.initialize(MLDSAParameterSpec.ml_dsa_44, katRandom);

        KeyPair kp = kpg.generateKeyPair();

        SubjectPublicKeyInfo pubInfo = SubjectPublicKeyInfo.getInstance(kp.getPublic().getEncoded());

        ASN1BitString pubSeq = pubInfo.getPublicKeyData();

        assertTrue(Arrays.areEqual(pubSeq.getOctets(), pubK));

        PrivateKeyInfo privInfo = PrivateKeyInfo.getInstance(kp.getPrivate().getEncoded());
        ASN1OctetString seq = ASN1OctetString.getInstance(privInfo.parsePrivateKey());

        assertTrue(Arrays.areEqual(seq.getOctets(), privK));

        Signature sig = Signature.getInstance("ML-DSA", "BC");

        sig.initSign(kp.getPrivate());

        sig.update(msg, 0, msg.length);

        byte[] genS = sig.sign();

        assertTrue(Arrays.areEqual(s, genS));

        sig = Signature.getInstance("ML-DSA", "BC");

        sig.initVerify(kp.getPublic());

        sig.update(msg, 0, msg.length);

        assertTrue(sig.verify(s));

        // check randomisation

        sig.initSign(kp.getPrivate(), new SecureRandom());

        sig.update(msg, 0, msg.length);

        genS = sig.sign();

        assertFalse(Arrays.areEqual(s, genS));

        sig = Signature.getInstance("ML-DSA", "BC");

        sig.initVerify(kp.getPublic());

        sig.update(msg, 0, msg.length);

        assertTrue(sig.verify(s));
    }

    private static class RiggedRandom
            extends SecureRandom
    {
        public void nextBytes(byte[] bytes)
        {
            for (int i = 0; i != bytes.length; i++)
            {
                bytes[i] = (byte)(i & 0xff);
            }
        }
    }
}
