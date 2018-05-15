package org.bouncycastle.crypto.test;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.agreement.DHAgreement;
import org.bouncycastle.crypto.agreement.DHBasicAgreement;
import org.bouncycastle.crypto.agreement.DHUnifiedAgreement;
import org.bouncycastle.crypto.generators.DHBasicKeyPairGenerator;
import org.bouncycastle.crypto.generators.DHKeyPairGenerator;
import org.bouncycastle.crypto.generators.DHParametersGenerator;
import org.bouncycastle.crypto.params.DHKeyGenerationParameters;
import org.bouncycastle.crypto.params.DHParameters;
import org.bouncycastle.crypto.params.DHPrivateKeyParameters;
import org.bouncycastle.crypto.params.DHPublicKeyParameters;
import org.bouncycastle.crypto.params.DHUPrivateParameters;
import org.bouncycastle.crypto.params.DHUPublicParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

public class DHTest
    extends SimpleTest
{
    private BigInteger g512 = new BigInteger("153d5d6172adb43045b68ae8e1de1070b6137005686d29d3d73a7749199681ee5b212c9b96bfdcfa5b20cd5e3fd2044895d609cf9b410b7a0f12ca1cb9a428cc", 16);
    private BigInteger p512 = new BigInteger("9494fec095f3b85ee286542b3836fc81a5dd0a0349b4c239dd38744d488cf8e31db8bcb7d33b41abb9e5a33cca9144b1cef332c94bf0573bf047a3aca98cdf3b", 16);

    private BigInteger g768 = new BigInteger("7c240073c1316c621df461b71ebb0cdcc90a6e5527e5e126633d131f87461c4dc4afc60c2cb0f053b6758871489a69613e2a8b4c8acde23954c08c81cbd36132cfd64d69e4ed9f8e51ed6e516297206672d5c0a69135df0a5dcf010d289a9ca1", 16);
    private BigInteger p768 = new BigInteger("8c9dd223debed1b80103b8b309715be009d48860ed5ae9b9d5d8159508efd802e3ad4501a7f7e1cfec78844489148cd72da24b21eddd01aa624291c48393e277cfc529e37075eccef957f3616f962d15b44aeab4039d01b817fde9eaa12fd73f", 16);

    private BigInteger  g1024 = new BigInteger("1db17639cdf96bc4eabba19454f0b7e5bd4e14862889a725c96eb61048dcd676ceb303d586e30f060dbafd8a571a39c4d823982117da5cc4e0f89c77388b7a08896362429b94a18a327604eb7ff227bffbc83459ade299e57b5f77b50fb045250934938efa145511166e3197373e1b5b1e52de713eb49792bedde722c6717abf", 16);
    private BigInteger  p1024 = new BigInteger("a00e283b3c624e5b2b4d9fbc2653b5185d99499b00fd1bf244c6f0bb817b4d1c451b2958d62a0f8a38caef059fb5ecd25d75ed9af403f5b5bdab97a642902f824e3c13789fed95fa106ddfe0ff4a707c85e2eb77d49e68f2808bcea18ce128b178cd287c6bc00efa9a1ad2a673fe0dceace53166f75b81d6709d5f8af7c66bb7", 16);

    public String getName()
    {
        return "DH";
    }

    private void testDH(
        int         size,
        BigInteger  g,
        BigInteger  p)
    {
        DHKeyPairGenerator kpGen = getDHKeyPairGenerator(g, p);

        //
        // generate first pair
        //
        AsymmetricCipherKeyPair     pair = kpGen.generateKeyPair();

        DHPublicKeyParameters       pu1 = (DHPublicKeyParameters)pair.getPublic();
        DHPrivateKeyParameters      pv1 = (DHPrivateKeyParameters)pair.getPrivate();
        //
        // generate second pair
        //
        pair = kpGen.generateKeyPair();

        DHPublicKeyParameters       pu2 = (DHPublicKeyParameters)pair.getPublic();
        DHPrivateKeyParameters      pv2 = (DHPrivateKeyParameters)pair.getPrivate();

        //
        // two way
        //
        DHAgreement    e1 = new DHAgreement();
        DHAgreement    e2 = new DHAgreement();

        e1.init(pv1);
        e2.init(pv2);

        BigInteger  m1 = e1.calculateMessage();
        BigInteger  m2 = e2.calculateMessage();

        BigInteger   k1 = e1.calculateAgreement(pu2, m2);
        BigInteger   k2 = e2.calculateAgreement(pu1, m1);

        if (!k1.equals(k2))
        {
            fail(size + " bit 2-way test failed");
        }
    }

    private void testDHBasic(
        int         size,
        int         privateValueSize,
        BigInteger  g,
        BigInteger  p)
    {
        DHBasicKeyPairGenerator kpGen = getDHBasicKeyPairGenerator(g, p, privateValueSize);

        //
        // generate first pair
        //
        AsymmetricCipherKeyPair     pair = kpGen.generateKeyPair();

        DHPublicKeyParameters       pu1 = (DHPublicKeyParameters)pair.getPublic();
        DHPrivateKeyParameters      pv1 = (DHPrivateKeyParameters)pair.getPrivate();

        checkKeySize(privateValueSize, pv1);
        //
        // generate second pair
        //
        pair = kpGen.generateKeyPair();

        DHPublicKeyParameters       pu2 = (DHPublicKeyParameters)pair.getPublic();
        DHPrivateKeyParameters      pv2 = (DHPrivateKeyParameters)pair.getPrivate();

        checkKeySize(privateValueSize, pv2);
        //
        // two way
        //
        DHBasicAgreement    e1 = new DHBasicAgreement();
        DHBasicAgreement    e2 = new DHBasicAgreement();

        e1.init(pv1);
        e2.init(pv2);

        BigInteger   k1 = e1.calculateAgreement(pu2);
        BigInteger   k2 = e2.calculateAgreement(pu1);

        if (!k1.equals(k2))
        {
            fail("basic " + size + " bit 2-way test failed");
        }
    }

    private void checkKeySize(
        int privateValueSize,
        DHPrivateKeyParameters priv)
    {
        if (privateValueSize != 0)
        {
            if (priv.getX().bitLength() != privateValueSize)
            {
                fail("limited key check failed for key size " + privateValueSize);
            }
        }
    }

    private void testGPWithRandom(
        DHKeyPairGenerator kpGen)
    {
        //
        // generate first pair
        //
        AsymmetricCipherKeyPair     pair = kpGen.generateKeyPair();

        DHPublicKeyParameters       pu1 = (DHPublicKeyParameters)pair.getPublic();
        DHPrivateKeyParameters      pv1 = (DHPrivateKeyParameters)pair.getPrivate();
        //
        // generate second pair
        //
        pair = kpGen.generateKeyPair();

        DHPublicKeyParameters       pu2 = (DHPublicKeyParameters)pair.getPublic();
        DHPrivateKeyParameters      pv2 = (DHPrivateKeyParameters)pair.getPrivate();

        //
        // two way
        //
        DHAgreement    e1 = new DHAgreement();
        DHAgreement    e2 = new DHAgreement();

        e1.init(new ParametersWithRandom(pv1, new SecureRandom()));
        e2.init(new ParametersWithRandom(pv2, new SecureRandom()));

        BigInteger   m1 = e1.calculateMessage();
        BigInteger   m2 = e2.calculateMessage();

        BigInteger   k1 = e1.calculateAgreement(pu2, m2);
        BigInteger   k2 = e2.calculateAgreement(pu1, m1);
        
        if (!k1.equals(k2))
        {
            fail("basic with random 2-way test failed");
        }
    }
    
    private void testSimpleWithRandom(
        DHBasicKeyPairGenerator kpGen)
    {
        //
        // generate first pair
        //
        AsymmetricCipherKeyPair     pair = kpGen.generateKeyPair();

        DHPublicKeyParameters       pu1 = (DHPublicKeyParameters)pair.getPublic();
        DHPrivateKeyParameters      pv1 = (DHPrivateKeyParameters)pair.getPrivate();
        //
        // generate second pair
        //
        pair = kpGen.generateKeyPair();

        DHPublicKeyParameters       pu2 = (DHPublicKeyParameters)pair.getPublic();
        DHPrivateKeyParameters      pv2 = (DHPrivateKeyParameters)pair.getPrivate();

        //
        // two way
        //
        DHBasicAgreement    e1 = new DHBasicAgreement();
        DHBasicAgreement    e2 = new DHBasicAgreement();

        e1.init(new ParametersWithRandom(pv1, new SecureRandom()));
        e2.init(new ParametersWithRandom(pv2, new SecureRandom()));

        BigInteger   k1 = e1.calculateAgreement(pu2);
        BigInteger   k2 = e2.calculateAgreement(pu1);

        if (!k1.equals(k2))
        {
            fail("basic with random 2-way test failed");
        }
    }

    private DHBasicKeyPairGenerator getDHBasicKeyPairGenerator(
        BigInteger g,
        BigInteger p,
        int        privateValueSize)
    {
        DHParameters                dhParams = new DHParameters(p, g, null, privateValueSize);
        DHKeyGenerationParameters   params = new DHKeyGenerationParameters(new SecureRandom(), dhParams);
        DHBasicKeyPairGenerator     kpGen = new DHBasicKeyPairGenerator();

        kpGen.init(params);
        
        return kpGen;
    }
    
    private DHKeyPairGenerator getDHKeyPairGenerator(
        BigInteger g,
        BigInteger p)
    {
        DHParameters                dhParams = new DHParameters(p, g);
        DHKeyGenerationParameters   params = new DHKeyGenerationParameters(new SecureRandom(), dhParams);
        DHKeyPairGenerator          kpGen = new DHKeyPairGenerator();

        kpGen.init(params);
        
        return kpGen;
    }
    
    /**
     * this test is can take quiet a while
     */
    private void testGeneration(
        int         size)
    {
        DHParametersGenerator       pGen = new DHParametersGenerator();

        pGen.init(size, 10, new SecureRandom());

        DHParameters                dhParams = pGen.generateParameters();

        if (dhParams.getL() != 0)
        {
            fail("DHParametersGenerator failed to set J to 0 in generated DHParameters");
        }

        DHKeyGenerationParameters   params = new DHKeyGenerationParameters(new SecureRandom(), dhParams);

        DHBasicKeyPairGenerator     kpGen = new DHBasicKeyPairGenerator();

        kpGen.init(params);

        //
        // generate first pair
        //
        AsymmetricCipherKeyPair     pair = kpGen.generateKeyPair();

        DHPublicKeyParameters       pu1 = (DHPublicKeyParameters)pair.getPublic();
        DHPrivateKeyParameters      pv1 = (DHPrivateKeyParameters)pair.getPrivate();
        
        //
        // generate second pair
        //
        params = new DHKeyGenerationParameters(new SecureRandom(), pu1.getParameters());

        kpGen.init(params);

        pair = kpGen.generateKeyPair();

        DHPublicKeyParameters       pu2 = (DHPublicKeyParameters)pair.getPublic();
        DHPrivateKeyParameters      pv2 = (DHPrivateKeyParameters)pair.getPrivate();

        //
        // two way
        //
        DHBasicAgreement    e1 = new DHBasicAgreement();
        DHBasicAgreement    e2 = new DHBasicAgreement();

        e1.init(new ParametersWithRandom(pv1, new SecureRandom()));
        e2.init(new ParametersWithRandom(pv2, new SecureRandom()));

        BigInteger   k1 = e1.calculateAgreement(pu2);
        BigInteger   k2 = e2.calculateAgreement(pu1);

        if (!k1.equals(k2))
        {
            fail("basic with " + size + " bit 2-way test failed");
        }
    }

    private void testBounds()
    {
         BigInteger p1 = new BigInteger("00C8028E9151C6B51BCDB35C1F6B2527986A72D8546AE7A4BF41DC4289FF9837EE01592D36C324A0F066149B8B940C86C87D194206A39038AE3396F8E12435BB74449B70222D117B8A2BB77CB0D67A5D664DDE7B75E0FEC13CE0CAF258DAF3ADA0773F6FF0F2051D1859929AAA53B07809E496B582A89C3D7DA8B6E38305626621", 16);
         BigInteger g1 = new BigInteger("1F869713181464577FE4026B47102FA0D7675503A4FCDA810881FAEC3524E6DBAEA9B96561EF7F8BEA76466DF11C2F3EB1A90CC5851735BF860606481257EECE6418C0204E61004E85D7131CE54BCBC7AD67E53C79DCB715E7C8D083DCD85D728283EC8F96839B4C9FA7C0727C472BEB94E4613CAFA8D580119C0AF4BF8AF252", 16);
         int l1 = 1023;

         BigInteger p2 = new BigInteger("00B333C98720220CC3946F494E25231B3E19F9AD5F6B19F4E7ABF80D8826C491C3224D4F7415A14A7C11D1BE584405FED12C3554F103E56A72D986CA5E325BB9DE07AC37D1EAE5E5AC724D32EF638F0E4462D4C1FC7A45B9FD3A5DF5EC36A1FA4DAA3FBB66AA42B1B71DF416AB547E987513426C7BB8634F5F4D37705514FDC1E1", 16);
         BigInteger g2 = new BigInteger("2592F5A99FE46313650CCE66C94C15DBED9F4A45BD05C329986CF5D3E12139F0405A47C6385FEA27BFFEDC4CBABC5BB151F3BEE7CC3D51567F1E2B12A975AA9F48A70BDAAE7F5B87E70ADCF902490A3CBEFEDA41EBA8E12E02B56120B5FDEFBED07F5EAD3AE020DF3C8233216F8F0D35E13A7AE4DA5CBCC0D91EADBF20C281C6", 16);
         int l2 = 1024;

        DHKeyGenerationParameters   params1 = new DHKeyGenerationParameters(new SecureRandom(), new DHParameters(p1, g1, null, l1));
        DHKeyGenerationParameters   params2 = new DHKeyGenerationParameters(new SecureRandom(), new DHParameters(p2, g2, null, l2));

        DHBasicKeyPairGenerator     kpGen = new DHBasicKeyPairGenerator();

        kpGen.init(params1);
        kpGen.init(params2);
    }

    private void testCombinedTestVector1()
    {
        // Test Vector from NIST sample data

        BigInteger P = new BigInteger("eedb3431b31d30851ddcd4dce57e1b8fc3b83cc7913bc049281d713d9f8fa91bfd0fde2e1ec5eb45a0d6483cfa6b5055ffa88622a1aa83b9f9c1df561e88b702866f17af2defea0b04cf3fbdd817140ad49c415909fc2bb2c5d160b77273e958a181bf73cf72118e1c8670d53d0e459d14d61ecb5b7c7f63a9cb019cd66aecb3a01d0402f1c18218f142653f4bc922e5baa35964b7432f311fa5a9b34e3b91582db366ad1493f25ea659540f87758ae34678dc864fb2c9d4aba18cb757285292c7d0bac73cc4632a2d54b89f2dc9656d1c50edd49dcbe2102510c70563a96f35dd8a21f0fdc5a1e23ce31fce0ee3023eafdca623508ffd2412fe4dc5b5dd0f75", 16);
        BigInteger Q = new BigInteger("e90a78d5da01e926462e5c17a61ff97b09b6ac18f9137e7b99298705", 16);
        BigInteger G = new BigInteger("9da3567e2f7396dd2ee4716d3477a53a47f811b2275a95ed07024d7231b739c79e88e5377479b23d460a41f981b1af619915e4d8b2dabf2cb716168d02dfb81e76048e23fff6c773f496b2ac3ae06e2eb12c39787a8244452aef404ce631aec9cf4027eefae492ce55517db0af3939354c5414e23205ae3bcd17faedecf80101fa75c619249a43b41aa15ee2d7699ee32e227b641129fe1c78b20c6655b09fa7fead338e179b4b4416c359b16e3773d141e1a876b7ee4281b61120607717f7edc8da8de42b16b54d0802d67d41fc173cd33227436f7c66bd2fe711b37fb0162543c268857414f4188f243fbf92e128388329c9f2df8db4e7808ab539891da798", 16);

        DHParameters p = new DHParameters(P, G, Q);
        
        AsymmetricCipherKeyPair U1 = new AsymmetricCipherKeyPair(
            new DHPublicKeyParameters(
                new BigInteger("e485cd4b82e82dafd35f89d40361049e6100c16b17ca156d072832319a40bf7a3f5081182397b8fbd9d33391896bb35d9cc890d8c0a9e5b642b773ce0690f1bbd4596a9604708edb9c27f45117a7395b7407b43eebd8b82bef4a925e2a93185df21fbf012ec9059a9c9efc0b64afe0505aa1864d79a2a9833863c16163b48c9fcc26a9b9e2741097bdeabc2b7208589e4154e1de7ecf77e928668b28abb8113b322c6d426701df979d47ccd50d493b7fb6f20050c3e67cb876c1550d8c8677527600eab07196213252bd9a48d5023788fdb4b65f85144cf6654e092550646be4882125b286ced6578eedc981304ff88725e4138f90a7a4a07c94105d796b038f", 16), p),
            new DHPrivateKeyParameters(
                new BigInteger("8a10c0be8f4efaf3019b99698bc4c102f2dac93b993d52ab10ae93f0", 16), p));

        AsymmetricCipherKeyPair U2 = new AsymmetricCipherKeyPair(
            new DHPublicKeyParameters(
                new BigInteger("3e84fbbb785bbdc43881b04ec6221b69a557b8b708d72cec8627a8342787554702d5021153ff1246ba5311553f740835c4b82ebc28c5fac05ad37f6c619649750e8dc41af9176af0099f18d36ee43535e7f35fb5f70a37b25dedd87cb6035bb938531c0430cee9c5c8f4321eae72590122bff1f636dcd6a32116ea3945d23a17acc1bfd1e7ad12390e6e13b456bc4a613b1356a7ca95c2660ac5c9f064a6b9c6d584c7e23bc1ff56745d92d0efc06384b3f59125f7c0918ae3a40074d229e22d8ca7573f9fbe89bc7afb344498d6a85b823e1fa20c3d6eccdd69abafe5e43273e71b6d32aa8dc3a349ec4ae41304e6e159c2e5c4b1555a538d58b46a4c8c87d9", 16), p),
            new DHPrivateKeyParameters(
                new BigInteger("5cb398bfbc3f69744de1f9611e03ab97aba0c5dbe1f6d74ac60fecdf", 16), p));

        AsymmetricCipherKeyPair V1 = new AsymmetricCipherKeyPair(
            new DHPublicKeyParameters(
                new BigInteger("2d6e1bb1ed6cc967027f2eb76d069369ac26f38fc87110fe55cc6487988a7d7bf2525a1b65cd02e30fcaa12d626f3b18d9191e6dcbf9fbe4b1f421dd2cb8ca804a7ca535c05bcb850561edb477eafe0a1e1e2468e89bb58899293d65cde98db5200b5eb32b1d80d4489fbab14a68f74453513658bda56067e8b41add0f13f5980ceb77c52f205e3d8b36f436ff0b313860197972de0da8b554b47091b8a69cf6ce7efd6cae6e17f090e0f71fc5332a9999cf880ff5c031132463b0eb56083885cee842f85540418b68d0250b18181b0dfb9487e39aad1d0402dc910cf679fd87d765222812ec66cf0a981f950de94b0fd1f45370bc2176748d20fe099c1f498c", 16), p),
            new DHPrivateKeyParameters(
                new BigInteger("9b6038b952d3491d937a41e1bf8857bd79b80a96c99783a96ff1ef93", 16), p));

        AsymmetricCipherKeyPair V2 = new AsymmetricCipherKeyPair(
            new DHPublicKeyParameters(
                new BigInteger("991805c775da39e0b92dc71f212e332cbab2b62a86114836bbe091c5ba2ce12cca5011483e220c0f24bba23f24a32c2c11b966064beba99b0b21eb19c7f46b328dc30af094ec116248e6f3f856aab622da4eb36b6056d7c5a3e0a0f1c45acc24321fccd1d0e0f4503e3e3aae3748ae6adeb1b85e0f708b4877b7a8d97acab093a57820b9d861da6d919126ae1c0b2d28dccca03a1808c03d5c5b6847d5e43a70b0a07190ced3ccf419e9f790281cf4676cad5dc6c7d3591a9fde2251850e072ffbc0411d8559460303c56738a1dbf76c8dd165b62a407e8cac9455c9257016fa0c7892cbcb978489a909f74d38d10746c1d5756329607ab0479c994c5d6f30e3", 16), p),
            new DHPrivateKeyParameters(
                new BigInteger("2775ab7578d5c0e18d12ed02f8c38ddfe272712902ee6a256270b041", 16), p));
        
        byte[] x = calculateUnifiedAgreement(U1, U2, V1, V2);

        if (x == null
            || !areEqual(Hex.decode("0f028c915a5ff77f5997791b66f08261995f7b459a574d66412f00afe5af4b838da0b9a4ed371077f1160f063844bca86ae83838cce0974d130f489532a8aeee5d55df17c13a15f79f27144aa3533665a47867f3eb43feb963ac2201d2766fb62a3979c19411c94cedf2c283b59fc616fbeeca585deb726fc7002900dc300e7b9bc055261708fee0f1f9b90de4f3720b7ec85d68745f41d495f1001dd7ccbbacf42ff2edc28e33454c5c59897d9782142db3f47972e2a79f16028f5fc6cdce4c729c57e9f63b55e25e80e3663528942b79749d7d66f7d84d4c8c4e877e221a8e06c7f001cd50b008086a4b0981e5fe000b7896dee152b24ed9cdb9907a5d64f0e4225b3cba8268c45c0846a60a697218a683e1b33843cb0153d8634769882a7fef5db4653d827bd75b54dda96666944b5d836b875d76936f73520e57be069f6aba7c36d42fc07be3e7ea49d0dabfad3177aa673553ba93a990cb79df9bcd8fa979f81c75b280cb99ff8e09713546cae8dbaea1021d2c29902793d483f29c1153f432e8b00e039286b085df0260d4949703a4a7a46492d1cb586d1845182c5b5461a432c5ebe60650de40e9e25502a0dfb931c4d5e5d9b624dcab3cbb5bf7cc51e5dbf35cd7029e724840c660dd4a6014de92a2bbb8a1b6ce28f6448d28cf1975017f66bc6904d244fe91ec39e509568d1c8256fa79931875b7ab69e29e432cce"), x))
        {
            fail("DH Combined Test Vector #1 agreement failed");
        }
    }

    private void testCombinedTestVector2()
    {
        // Test Vector from NIST sample data

        BigInteger P = new BigInteger("ea40cd647d0a1d3bcbdfa721a837e4d4dfd328340892a00aa2317f2fc532fe1e185d4ef0718281959943fc949964e542310deb687f7fcc45696c829a491b7dc5c46fff01673e71d92520465b4115dbb7edaeb32ec2688d0a5a9be93a322f3023b96d5f54e02d4a72dec479f68b40caff79f810f3a5cdaa3bda9eb87151b4c0663ceef4b50ca22ac63e4ab1343978e8ec148b5523734b23aa9ca92a21ca1cbe652c9a01b1724a1b10285778287cb5bf87c45e45dc54998e5e5308c00003131be4a62add4f5acbb0c4e2229e0fccd1633e4cf024f96dcbf012e5b629394500b1b5ceb6707957bde445671ba9a1d5b9a7d1dfe2f1419d1abf236b4b49bcfd7563df", 16);
        BigInteger Q = new BigInteger("aa6b31da31408f637670a1fc36ca3625a5eebea9bdcc4398124bb9a006ac21f1", 16);
        BigInteger G = new BigInteger("380ad19f75e5c666aa24daf545d74c51a4374f9002de09744bc338a33a3ab2017fdeb59f1f8552125ade4dceb7094d125ffad694662e3fe924d23c7a404806631e353887bbc4bf9f892f581880975918aca5b8a7d5108b791469f2e35f0a4095ce253bec246a8cdce190507018a4f844685eb2e0ba0146d5bb2d7ff7f1c5624fa2d7f6d20834c453457eb0227c26ae5d422cde461cfe1cd2f5ff909388dcd6ccdbfb8617b54d9038c1b9b1b2f15febbd5215db893f3a8f340bd18ac74d025a63b321ec537fa5d2c04c651f0431f75bc490ddd2a846595c6d10d0a085ab3835d025a334cdb0b25c3d993fa22aecaf5f87ca417a7aa278cb765344195f2a45201b", 16);

        DHParameters p = new DHParameters(P, G, Q);

        AsymmetricCipherKeyPair U1 = new AsymmetricCipherKeyPair(
            new DHPublicKeyParameters(
                new BigInteger("a2c43dc18321063dac3cd7793fb3a6cc3b38cbce99f233ba295660aa6cbba1449b0783acb7da1118bd0530f022336a2bb8845ac26bb71c3647369e8aa29ef7b5ddc4a3b4fe70291c9acf1bc1ce5666a3401b885fd7b1906ed27a985efdb643464398036ed79eb1a79cd7b88c5bfa4418df6439ac2297b946f125f7086537082f2144545da570835b23f27ebd400ceae6670168fece4ce3780a59d6eebb3a76f91de308d4aa9a1617b4005b6b089af5c5247af6a5dea1693861151e0a5aaa4b86884ab2969f5bc3008f19ac54118939b2efccf307dc2e3aa675aea0d80dcaec7160408d6e12b0b041544c831b9ae3d06b5d51e2e77035f0b5439fb375a9bd7664", 16), p),
            new DHPrivateKeyParameters(
                new BigInteger("7b4957b799a08816f9c48c2aff5dcc0aa6ad93a765a664e67899f09d1fa8949e", 16), p));

        AsymmetricCipherKeyPair U2 = new AsymmetricCipherKeyPair(
            new DHPublicKeyParameters(
                new BigInteger("5ceca3f30cb6eb8bef123518d9b569fb9df47ac54944e381da3f69ab4a3f0484e49ea8e54d87b2bcad6f78c82f9a1969b72c7b1314ccf2ff7aa857e69ae24dbbce023f8d3cfcb2b5fe942750597b1ada12b685bb12c6ddfddf0a9d2b95e0692d431f5735b71d456fabc7362581cad88ca97b69cf185ec2d6097b07a1da80291c4d93285b21604540dc1da0807009b8f708e4eb4bdd40672b875076d5f4e712b54922c6506de4280f2cf8b34d78ea59a91dd45c7eee8cd77d8640af48342ea348abed040f7dd085181bda8f9ce88cc602407ae91b4fcb051cfcff7e7479fb6e24f6b7fb013d5b3d2ccc3dc3088c331fc9644b73e1b47e3f585f97e6f2c57e9983", 16), p),
            new DHPrivateKeyParameters(
                new BigInteger("8f9fe1ecd00b427a211f9d52b973aad9451b5985757a2204473f06de07eb39e2", 16), p));

        AsymmetricCipherKeyPair V1 = new AsymmetricCipherKeyPair(
            new DHPublicKeyParameters(
                new BigInteger("b823ca4d470c714efb57420cc50acbb56eb4a4664abb3fe233496c2a0f70e52a0af08f87490724819d8bfc10203dc62b38ee032f5e14e612e1b23d5b014359ab4fe3584f49475c9d117f9ad89511d88c79dcc284d39d722939b0b5d24ad7374af70db712344755fc54502d0ae428860f63fcdcd9537c0f89f451ada1a30676481154129de022019e5a6ac1c117820896ebd97d06db887d6fd088ab71ad0fd2f3c87a015abe428aeadee7a8a65a7b823edcf4b7d9b2faf98691126b885e5804bac1a8fa1d05c186de218816e0aa75e939b731621a424b39d19e47a81d3638ff3d663e38a802361fb9bd1e79b2f3d1f4955b3d7d63bcb373f2ee70659a270f5087", 16), p),
            new DHPrivateKeyParameters(
                new BigInteger("2c8c6202bb519b17361418f48ef346328db6be65b4aa6a25561e165b6958682e", 16), p));

        AsymmetricCipherKeyPair V2 = new AsymmetricCipherKeyPair(
            new DHPublicKeyParameters(
                new BigInteger("dae7f69a4a318f506181bd97320777e9256dcf992057eb951585fbd5b6e22e0a57255f316315e462ee38e15a0e5c5b9fc3f6f0611929bfe681f0d093cdcda18e35e13f09d5c73cbab5f659b2c55669410e5a772b621acbfa365db6046b08bce1bac4c379ad0f2bee10eddb040645ab75d5888c93e91efdc442053e5e935541b80afa911881daa91488bceab9585facbbdb010575387eac4f6657fbdc85a37dedbfccbd9b37d671861c5853de9078bdf905f15b191f2dcc1c93ee7258dc6854a8d3882ff4f03753373305fa4a00a839c3853e128f51004a17641f37ed9035665c4a6d6240cbeefb9c36b618a50e3b75d6128f732b34d81ce8b316ddefe8c0630d", 16), p),
            new DHPrivateKeyParameters(
                new BigInteger("35f5bf981241cff39e43b93bf31f5612a364595a881e75315de0b42b82f0d596", 16), p));

        byte[] x = calculateUnifiedAgreement(U1, U2, V1, V2);

        if (x == null
            || !areEqual(Hex.decode("6d1eae28340c2095ab915b6655c96d23986c49e53f38de42a9c906eeeae3686744855b940de8377ad23053d923116f6dce7c91eea69714092a4e182cef01b362937c9bc66cc892948e79bac85bf0b9ee5c402c7725def46f754e5cd743e89247e84a4fe6e50b249c7aecf62114cb3beb6a0f8af8b0f3a19799c67372109fe0e01af6517d4108888cd3864b801a8566516b454219ee74b86a2e1a4cfbb2407198a1382858b947f9258404764fee9a0a99198c594fee426e04453b41051cfa22359d2b10d425142045b1a186056413203f4553ce0d7977012f1d3aa3df571f041f7422d4518da7abdf5a32bbbc86615cd2217b73719cb0b5ee5228a74ed0cb8202b862c68e46ab8282a482a9c94365e3dcb3b9b511bc65e7741f7d90f1180ef9c926ed9209cb10291d0ea472e675ac7704244723d788985aa6f5a73c83be4cdaba402453dfa572ac6d5bafb51b130556481e98a5ab5ede13364b886fbbf57f282b8f560f4ceafb2f29d953c8244aa3fea0c227a1a88e012e814267ecf36ac72793acf2ee02713d8980f30bc9231aae91a8181ed4645aa969625990cbdc7f4f646929132ef73354950c2490f91847a3350ece763a1869f6e446e4995296d4c024bf6998dd11aea59220e81e1aade984ba650150621f17e4bbca5f0f49fd21924c3a605d1e7e4fd3e32b93e1df6cd6a0d28cd9105537b513144e8ad1d3007bffbb15"), x))
        {
            fail("DH Combined Test Vector #2 agreement failed");
        }
    }

    private byte[] calculateUnifiedAgreement(
        AsymmetricCipherKeyPair U1,
        AsymmetricCipherKeyPair U2,
        AsymmetricCipherKeyPair V1,
        AsymmetricCipherKeyPair V2)
    {
        DHUnifiedAgreement u = new DHUnifiedAgreement();
        u.init(new DHUPrivateParameters(
            (DHPrivateKeyParameters)U1.getPrivate(),
            (DHPrivateKeyParameters)U2.getPrivate(),
            (DHPublicKeyParameters)U2.getPublic()));
        byte[] ux = u.calculateAgreement(new DHUPublicParameters(
            (DHPublicKeyParameters)V1.getPublic(),
            (DHPublicKeyParameters)V2.getPublic()));

        DHUnifiedAgreement v = new DHUnifiedAgreement();
        v.init(new DHUPrivateParameters(
            (DHPrivateKeyParameters)V1.getPrivate(),
            (DHPrivateKeyParameters)V2.getPrivate(),
            (DHPublicKeyParameters)V2.getPublic()));
        byte[] vx = v.calculateAgreement(new DHUPublicParameters(
            (DHPublicKeyParameters)U1.getPublic(),
            (DHPublicKeyParameters)U2.getPublic()));

        if (areEqual(ux, vx))
        {
            return ux;
        }

        return null;
    }
    
    public void performTest()
    {
        testDHBasic(512, 0, g512, p512);
        testDHBasic(768, 0, g768, p768);
        testDHBasic(1024, 0, g1024, p1024);

        testDHBasic(512, 64, g512, p512);
        testDHBasic(768, 128, g768, p768);
        testDHBasic(1024, 256, g1024, p1024);

        testDH(512, g512, p512);
        testDH(768, g768, p768);
        testDH(1024, g1024, p1024);

        testBounds();

        testCombinedTestVector1();
        testCombinedTestVector2();
        
        //
        // generation test.
        //
        testGeneration(256);
        
        //
        // with random test
        //
        DHBasicKeyPairGenerator     kpBasicGen = getDHBasicKeyPairGenerator(g512, p512, 0);
        
        testSimpleWithRandom(kpBasicGen);
        
        DHKeyPairGenerator          kpGen = getDHKeyPairGenerator(g512, p512);
        
        testGPWithRandom(kpGen);
        
        //
        // parameter tests
        //
        DHAgreement             dh = new DHAgreement();
        AsymmetricCipherKeyPair dhPair = kpGen.generateKeyPair();
        
        try
        {
            dh.init(dhPair.getPublic());
            fail("DHAgreement key check failed");
        }
        catch (IllegalArgumentException e)
        {
            // ignore
        }
        
        DHKeyPairGenerator      kpGen768 = getDHKeyPairGenerator(g768, p768);
        
        try
        {
            dh.init(dhPair.getPrivate());
            
            dh.calculateAgreement((DHPublicKeyParameters)kpGen768.generateKeyPair().getPublic(), BigInteger.valueOf(100));
            
            fail("DHAgreement agreement check failed");
        }
        catch (IllegalArgumentException e)
        {
            // ignore
        }
        
        DHBasicAgreement        dhBasic = new DHBasicAgreement();
        AsymmetricCipherKeyPair dhBasicPair = kpBasicGen.generateKeyPair();
 
        try
        {
            dhBasic.init(dhBasicPair.getPublic());
            fail("DHBasicAgreement key check failed");
        }
        catch (IllegalArgumentException e)
        {
            // expected
        }
        
        DHBasicKeyPairGenerator      kpBasicGen768 = getDHBasicKeyPairGenerator(g768, p768, 0);
        
        try
        {
            dhBasic.init(dhPair.getPrivate());
            
            dhBasic.calculateAgreement((DHPublicKeyParameters)kpBasicGen768.generateKeyPair().getPublic());
            
            fail("DHBasicAgreement agreement check failed");
        }
        catch (IllegalArgumentException e)
        {
            // expected
        }
    }

    public static void main(
        String[]    args)
    {
        runTest(new DHTest());
    }
}
