package org.bouncycastle.pqc.jcajce.provider.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import junit.framework.TestCase;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.jcajce.interfaces.SLHDSAKey;
import org.bouncycastle.jcajce.interfaces.SLHDSAPrivateKey;
import org.bouncycastle.jcajce.spec.SLHDSAParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.FixedSecureRandom;

/**
 * Test cases for the use of SLH-DSA with the provider.
 */
public class SLHDSATest
    extends TestCase
{
    // test vector courtesy the "Yawning Angel" GO implementation and the SUPERCOP reference implementation.
    byte[] msg = Strings.toByteArray("Cthulhu Fthagn --What a wonderful phrase!Cthulhu Fthagn --Say it and you're crazed!");

    public void setUp()
    {
        if (Security.getProvider(BouncyCastlePQCProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new BouncyCastlePQCProvider());
        }
        Security.addProvider(new BouncyCastleProvider());
    }

    public void testKeyFactory()
        throws Exception
    {
        KeyPairGenerator kpGen44 = KeyPairGenerator.getInstance("ML-DSA-44");
        KeyPair kp44 = kpGen44.generateKeyPair();

        KeyFactory kFact = KeyFactory.getInstance("SLH-DSA", "BC");

        String[] names = new String[] {
            "SLH-DSA-SHA2-128F",
            "SLH-DSA-SHA2-128S",
            "SLH-DSA-SHA2-192F",
            "SLH-DSA-SHA2-192S",
            "SLH-DSA-SHA2-256F",
            "SLH-DSA-SHA2-256S",
            "SLH-DSA-SHAKE-128F",
            "SLH-DSA-SHAKE-128S",
            "SLH-DSA-SHAKE-192F",
            "SLH-DSA-SHAKE-192S",
            "SLH-DSA-SHAKE-256F",
            "SLH-DSA-SHAKE-256S",
        };

        ASN1ObjectIdentifier[] oids = new ASN1ObjectIdentifier[] {
            NISTObjectIdentifiers.id_slh_dsa_sha2_128f,
            NISTObjectIdentifiers.id_slh_dsa_sha2_128s,
            NISTObjectIdentifiers.id_slh_dsa_sha2_192f,
            NISTObjectIdentifiers.id_slh_dsa_sha2_192s,
            NISTObjectIdentifiers.id_slh_dsa_sha2_256f,
            NISTObjectIdentifiers.id_slh_dsa_sha2_256s,
            NISTObjectIdentifiers.id_slh_dsa_shake_128f,
            NISTObjectIdentifiers.id_slh_dsa_shake_128s,
            NISTObjectIdentifiers.id_slh_dsa_shake_192f,
            NISTObjectIdentifiers.id_slh_dsa_shake_192s,
            NISTObjectIdentifiers.id_slh_dsa_shake_256f,
            NISTObjectIdentifiers.id_slh_dsa_shake_256s,
        };

        KeyPairGenerator kpGen768 = KeyPairGenerator.getInstance("ML-KEM-768");
        KeyPair kp768 = kpGen768.generateKeyPair();
        KeyPairGenerator kpGen1024 = KeyPairGenerator.getInstance("ML-KEM-1024");
        KeyPair kp1024 = kpGen1024.generateKeyPair();

        for (int i = 0; i != names.length; i++)
        {
            KeyPairGenerator kpGen = KeyPairGenerator.getInstance(names[i]);
            KeyPair kp = kpGen.generateKeyPair();

            tryKeyFact(KeyFactory.getInstance(names[i], "BC"), kp, kp44, "2.16.840.1.101.3.4.3.17");
            tryKeyFact(KeyFactory.getInstance(oids[i].toString(), "BC"), kp, kp44, "2.16.840.1.101.3.4.3.17");
        }
    }

    private void tryKeyFact(KeyFactory kFact, KeyPair kpValid, KeyPair kpInvalid, String oid)
        throws Exception
    {
        kFact.generatePrivate(new PKCS8EncodedKeySpec(kpValid.getPrivate().getEncoded()));
        kFact.generatePublic(new X509EncodedKeySpec(kpValid.getPublic().getEncoded()));

        try
        {
            kFact.generatePrivate(new PKCS8EncodedKeySpec(kpInvalid.getPrivate().getEncoded()));
            fail("no exception");
        }
        catch (InvalidKeySpecException e)
        {
            assertEquals("incorrect algorithm OID for key: " + oid, e.getMessage());
        }
        try
        {
            kFact.generatePublic(new X509EncodedKeySpec(kpInvalid.getPublic().getEncoded()));
            fail("no exception");
        }
        catch (InvalidKeySpecException e)
        {
            assertEquals("incorrect algorithm OID for key: " + oid, e.getMessage());
        }
    }

//    public void testSphincsDefaultKeyGen()
//        throws Exception
//    {
//        KeyPairGenerator kpg = KeyPairGenerator.getInstance("SLH-DSA", "BC");
//
//        kpg.initialize(new SLHDSAKeyGenParameterSpec(), new RiggedRandom());
//
//        KeyPair kp = kpg.generateKeyPair();
//
//        SLHDSAKey pub = (SLHDSAKey)kp.getPublic();
//
//        assertTrue(Arrays.areEqual(expSha2Pub, pub.getKeyData()));
//
//        SLHDSAKey priv = (SLHDSAKey)kp.getPrivate();
//
//        assertTrue(Arrays.areEqual(expSha2Priv, priv.getKeyData()));
//
//        KeyFactory keyFact = KeyFactory.getInstance("SLH-DSA", "BC");
//
//        SLHDSAKey pub2 = (SLHDSAKey)keyFact.generatePublic(new X509EncodedKeySpec(pub.getEncoded()));
//
//        assertTrue(Arrays.areEqual(expSha2Pub, pub2.getKeyData()));
//
//        SLHDSAKey priv2 = (SLHDSAKey)keyFact.generatePrivate(new PKCS8EncodedKeySpec(priv.getEncoded()));
//
//        assertTrue(Arrays.areEqual(expSha2Priv, priv2.getKeyData()));
//    }

    public void testPrivateKeyRecovery()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("SLH-DSA", "BC");

        kpg.initialize(SLHDSAParameterSpec.slh_dsa_sha2_128f, new RiggedRandom());

        KeyPair kp = kpg.generateKeyPair();

        KeyFactory kFact = KeyFactory.getInstance("SLH-DSA", "BC");

        SLHDSAKey privKey = (SLHDSAKey)kFact.generatePrivate(new PKCS8EncodedKeySpec(kp.getPrivate().getEncoded()));

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ObjectOutputStream oOut = new ObjectOutputStream(bOut);

        oOut.writeObject(privKey);

        oOut.close();

        ObjectInputStream oIn = new ObjectInputStream(new ByteArrayInputStream(bOut.toByteArray()));

        SLHDSAKey privKey2 = (SLHDSAKey)oIn.readObject();

        assertEquals(privKey, privKey2);

        assertEquals(kp.getPublic(), ((SLHDSAPrivateKey)privKey2).getPublicKey());
        assertEquals(((SLHDSAPrivateKey)privKey).getPublicKey(), ((SLHDSAPrivateKey)privKey2).getPublicKey());
    }

    public void testPublicKeyRecovery()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("SLH-DSA", "BC");

        kpg.initialize(SLHDSAParameterSpec.slh_dsa_sha2_128f, new RiggedRandom());

        KeyPair kp = kpg.generateKeyPair();

        KeyFactory kFact = KeyFactory.getInstance("SLH-DSA", "BC");

        SLHDSAKey pubKey = (SLHDSAKey)kFact.generatePublic(new X509EncodedKeySpec(kp.getPublic().getEncoded()));

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ObjectOutputStream oOut = new ObjectOutputStream(bOut);

        oOut.writeObject(pubKey);

        oOut.close();

        ObjectInputStream oIn = new ObjectInputStream(new ByteArrayInputStream(bOut.toByteArray()));

        SLHDSAKey pubKey2 = (SLHDSAKey)oIn.readObject();

        assertEquals(pubKey, pubKey2);
    }

//    public void testSphincsDefaultSha2KeyGen()
//        throws Exception
//    {
//        KeyPairGenerator kpg = KeyPairGenerator.getInstance("SLH-DSA", "BC");
//
//        kpg.initialize(new SLHDSAKeyGenParameterSpec(SLHDSAKeyGenParameterSpec.SHA512_256), new RiggedRandom());
//
//        KeyPair kp = kpg.generateKeyPair();
//
//        SLHDSAKey pub = (SLHDSAKey)kp.getPublic();
//
//        assertTrue(Arrays.areEqual(expSha2Pub, pub.getKeyData()));
//
//        SLHDSAKey priv = (SLHDSAKey)kp.getPrivate();
//
//        assertTrue(Arrays.areEqual(expSha2Priv, priv.getKeyData()));
//
//        KeyFactory keyFact = KeyFactory.getInstance("SLH-DSA", "BC");
//
//        SLHDSAKey pub2 = (SLHDSAKey)keyFact.generatePublic(new X509EncodedKeySpec(pub.getEncoded()));
//
//        assertTrue(Arrays.areEqual(expSha2Pub, pub2.getKeyData()));
//
//        SubjectPublicKeyInfo pkInfo = SubjectPublicKeyInfo.getInstance(pub2.getEncoded());
//
//        assertEquals(new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha512_256), SLHDSAKeyParams.getInstance(pkInfo.getAlgorithm().getParameters()).getTreeDigest());
//
//        SLHDSAKey priv2 = (SLHDSAKey)keyFact.generatePrivate(new PKCS8EncodedKeySpec(priv.getEncoded()));
//
//        assertTrue(Arrays.areEqual(expSha2Priv, priv2.getKeyData()));
//    }
//
//    public void testSphincsDefaultSha3KeyGen()
//        throws Exception
//    {
//        KeyPairGenerator kpg = KeyPairGenerator.getInstance("SLH-DSA", "BC");
//
//        kpg.initialize(new SLHDSAKeyGenParameterSpec(SLHDSAKeyGenParameterSpec.SHA3_256), new RiggedRandom());
//
//        KeyPair kp = kpg.generateKeyPair();
//
//        SLHDSAKey pub = (SLHDSAKey)kp.getPublic();
//
//        assertTrue(Arrays.areEqual(expSha3Pub, pub.getKeyData()));
//
//        SLHDSAKey priv = (SLHDSAKey)kp.getPrivate();
//
//        assertTrue(Arrays.areEqual(expSha3Priv, priv.getKeyData()));
//
//        KeyFactory keyFact = KeyFactory.getInstance("SLH-DSA", "BC");
//
//        SLHDSAKey pub2 = (SLHDSAKey)keyFact.generatePublic(new X509EncodedKeySpec(pub.getEncoded()));
//
//        assertTrue(Arrays.areEqual(expSha3Pub, pub2.getKeyData()));
//
//        SubjectPublicKeyInfo pkInfo = SubjectPublicKeyInfo.getInstance(pub2.getEncoded());
//
//        assertEquals(new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha3_256), SLHDSAKeyParams.getInstance(pkInfo.getAlgorithm().getParameters()).getTreeDigest());
//
//        SLHDSAKey priv2 = (SLHDSAKey)keyFact.generatePrivate(new PKCS8EncodedKeySpec(priv.getEncoded()));
//
//        assertTrue(Arrays.areEqual(expSha3Priv, priv2.getKeyData()));
//    }
//
//    public void testSphincsSha2Signature()
//        throws Exception
//    {
//        KeyPairGenerator kpg = KeyPairGenerator.getInstance("SLH-DSA", "BC");
//
//        kpg.initialize(new SLHDSAKeyGenParameterSpec(SLHDSAKeyGenParameterSpec.SHA512_256), new RiggedRandom());
//
//        KeyPair kp = kpg.generateKeyPair();
//
//        Signature sig = Signature.getInstance("SHA512withSPHINCSPlus", "BC");
//
//        sig.initSign(kp.getPrivate());
//
//        sig.update(msg, 0, msg.length);
//
//        byte[] s = sig.sign();
//
//        assertTrue(Arrays.areEqual(expSha2Sig, s));
//    }
//
//    public void testSphincsSha3Signature()
//        throws Exception
//    {
//        KeyPairGenerator kpg = KeyPairGenerator.getInstance("SLH-DSA", "BC");
//
//        kpg.initialize(new SLHDSAKeyGenParameterSpec(SLHDSAKeyGenParameterSpec.SHA3_256), new RiggedRandom());
//
//        KeyPair kp = kpg.generateKeyPair();
//
//        Signature sig = Signature.getInstance("SHA3-512withSPHINCSPlus", "BC");
//
//        sig.initSign(kp.getPrivate());
//
//        sig.update(msg, 0, msg.length);
//
//        byte[] s = sig.sign();
//
//        assertTrue(Arrays.areEqual(expSha3Sig, s));
//    }
//


    public void testSphincsRandomSigSHA2()
        throws Exception
    {
        SecureRandom random = new FixedSecureRandom(Hex.decode("7C9935A0B07694AA0C6D10E4DB6B1ADD2FD81A25CCB148032DCD739936737F2DB505D7CFAD1B497499323C8686325E4711E95F8A383854BA16A5DD3E25FF71D3"
            + "061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1"));
        byte[] msg = Hex.decode("D81C4D8D734FCBFBEADE3D3F8A039FAA2A2C9957E835AD55B22E75BF57BB556AC8");

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("SLH-DSA", "BC");

        kpg.initialize(SLHDSAParameterSpec.slh_dsa_sha2_128f, random);

        KeyPair kp = kpg.generateKeyPair();

        Signature sig = Signature.getInstance("SLH-DSA", "BC");

        sig.initSign(kp.getPrivate(), new FixedSecureRandom(Hex.decode("061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1")));

        sig.update(msg, 0, msg.length);

        byte[] s = sig.sign();
        byte[] expected = Hex.decode("97abf8262ecc8090d912c7aab1d951fffe1d9aa683a5565490221122f945825b2ac44a170d76442f7fc9d8479c05fc5c044bef94a5007cb258ed8efeb8f35e30837001c505dfe87196966c3b2591d7ffefded746660ffadac38782fc9e887bd324e744023b2520d60b6b6916b0285a42e4943c476434754b1651d1e8414070e65933d5916d66359b682c3568e893083e8fbc333f6bfa9e1584cfe0b688be3a5b22e6fefd77ff194597a17c275251598d94c68e73a1aee194f80ebbbf1a43eeacee49907870366d6eff0a85e609e5a8cdb3067b0412c5d4e62591f78ddb8b90c8fab47aa311c6731aaf1b8b6449173bb4062873ddc668978b4042d369bcb3e645369dfe15cd1d6216db70094597bd0c5b8c8cd81c1919fea04ff18683716c8b85c3508c5a21307f5c47810c27c4c3718deb7d714da3b1a21831f7f46e3cb81c42d89acca9040845a0207e1f05843df19bbef671e6bcffab6c13ee26c81bdae2823ab931933ab4528ab725c3c2483e3a4d85a07f089e74ab31a1813ce8593f0c3cd69e0fa54010ae149ca1a7c8afd0006b9244fde5fd3dc295c499bec19bb43527f7d6c9333ec9cab552b8971e130b689a7cea652239bea9efa132ce57a4c890ca5316b82425020114554b5c740d9c26b2ed736755984bdc83af939529254f9535f6926820d4fdbfec80ce88704c4a916e1a1641edf36dc9f2e0c4a68bec42e86c5cbc63acac1bb7126cb1046caeaf82e6c8655e82ef599a01bf9f4b7685b9b8957aa22e27ad8a5ee9addd86189562da654d69b90d31fb25e5a67ca50fff17fa8f7798ff7773d0b715b3958d043503b0240bf36936b4f8330c1c8b09fecd0303c5969d251f37423db8f83c79a093d7989fe2138cb696bdbed6e1dca17d5f18b5bbdb8629fc36a97599fc29aa792204976fabf826f670150df32d3f8670d600d3b703a1e2dcdc314cb9f4a42384ae90ee75967dbb2509077cf63ca42da5ec94ff32409440e47280bfb838a4e4fd2f0c078227718a6e7ab20fd0465e5aab1a3a29c30f0aecd55f0ff760862a1aa13c0db77411cdb48a34a95f716224fcd4a39bcd828f668b7d5632050a5256c644f2a46001998cfb11afaf70794495a6c61e33e8eb01011225364f9e8503ee9272a6174ae35622e3a0e808b2ec5aaf55c955680a5d4df3717f08207d4602a429b0f5adc0a071ce29b322bd3dacc755ddb2d3190c1b7f40b539293221ec98a206daaace78eb178cc47f3d5f2c3f224a6fc32090a0d1591c9d061125ced2be9e9585f2bb07f6b819b1da276e435a191fefbe6b9d44563da04f5731ae33fcd67ac1ec6875e0d1f8bfcad6d947d173cfcdd6aec22365af44e19168d1c0e6ba5f02b4402ec2b719f94d7097ead10f133e8cb675e4a34558ae77a032ce082e12c0c6badb5db19e92fd1303397db5753d9afa4d18e57f9cc26e8b5bd102b77eec3bc47f16babb451ed4a69ddff494f8a5dcfc1b5f8bb9400ed508214084a6065cb7d0a8efb8a073e3d91905dc8f926cbe20b6b3a0beb9a2d4dd12f70341e80ed59375ad2c38650f9bec4db036b344d7e8fd9919de04d14a4f19d2e91a123e65221267a7878121d61104a6594003e605f45e230892bf8d0fe13af8404adb1dc5876917a4dfe435edccc65f15bb7ce066fed76d3f02ca16be94187fb7f37b5379eea8da682f958d263c42f45cfa181fead2b31cf893de43a9041d414cb1ef4424d95741b8e3a74ce7b2dbe16ef0fb4d596196c09d493380d9b49c6180801bb52d6497fe9ab692a4afc98124e80d63ddd1313b7b9c31622fa1cfb7f7c413684fe15ee4b33b51e5bafaa6d887fd38c334b65dee3f729211f34b776cc9eff13eff293a1b3055f5ae083a50c667b988b5996a2db63528eb6fdd4083a5d53df26d6bf8a6b5a4b981cc835617d928358c1b3ccc5dc87e3fc46f4050af2fc020fee26b84af757715ab9f63797e48778b245c3aa5d9f6401dff64a475421b0c1bd59f0ec4c39f736cacf0dd9ebe2b170586902addf1493356e9e4646133e8a118975219b672451d9bf480ea3db866f18fe5675eaf70632abf47e11bb16e1e1ab38dde2ba9bc2f8365491c3f82ba6113c44a0c3d00e2c8eff095270409058b43dec29a4838bda04fedc68ef3c3e8e2d176ae5f98278033dca09237a03cf89edb2040b3e66087ca363e1c07046748f5cd515141c481ea4280d172c1d53c56fe813c29fc8a798fe362f6a578a63a0879bb25090a425fd4806698c94af3f0771f923fdb51953753b7a705a49c1c25c38ad203a696d40079274813b5e2168b930fc646c771ec48870521ba5eedabdb0d5ae3e5efa24e86132e0e487bc0bf42721125518a63d08f8bf7f05f4afbd2b939bf74a3ac892aed06d9fff944e2e333f951e99109247aa63265d2652bdc528b569639fd0dc16c03666300bd04873ab72f95e98bd6c9ec60b3f29c2f1bcd986100a70c37421352a4eebcb58cdafc4dbc867438887bae9b03ba8412e7b118e5381707c394cf428047f27a5255dd86bb77adad9fa1b8ec93f845009b58b837a04fed5197ca8d8acf4fec81e61b04a40bbecd67c30a490ebb2c18bba756b307607af3f121e772e5f89a90a138aacc92d613b0c36fc508fc940e7f515e5c0010351c865e954a8bdbc06e7ef209b776f77396e64d01a5eb13fa129377effcd77b14fba76f5c40fd9b9322a8396993df67b491eb462f2c38702ee91fcc18f9bd217fa4c54827a90b949a7d491420d544ca0ff11a22233563527404b8ddf0b04260346fa1042aee73fa1173d77a1d2485029efa6db4a7a79e169a7029c7be5ca51d864cb447c3f9de535e21a45d9703f00c62c0a61aa07ea6ba7a62ca524bb797df74731f6a7adc356a9adb84389a42770d105d7b8987e00ee3116d49dde57eba0b4ca7dc8eddebf3f08909a3e2c41a4f94431d59d15053b27d5d48f0bb531eaf938452562de653eb889ecbeb0920f7c9a8c3e4c3839ab32e54e4cabd7dcbcc922150271539db17845ca82d09064b262066e82b514322c8391693d6c5a90cf63f69a36bcaa995e9fa0896634ad316c9f20a987d72dd9ba90855c313af0bef8db57fd2af833371116617680fa0359eb91d1f4e9978141a83fe4ea4bb7b8c7d5a418b4709376f47b5b2c9e25b89e9d9cc45edf3a8ccd1ccff3e4e7b6f0d7d1e5a80e8d8882f2e726db164add7d9795f47261e0a668f7d83b25803182af4c2fcd68e1f2b142bbb8dc15c07edbe583d5cdcc0f3394934a6d4020bcb3511ae23fe6a6b9de1d1c503014b172f5814ff655f9dec0fc065644ecbfbe879daae4646ef510900fc73101190eb26cc0e563f1b5a204826d84397badfb796f32b70beed7848fe58970dbfc36fd70fd2697efcd069bd92bf9109d0e4aa9419616097e8a4ed00042c7376b3f03da61b61d959bd43b398de469092918c08213fe31e6e95a2cd650abdac660b15a765481a2f2bc57862593518d2a90d628b550ae9c5a3d9047e12cf4d060a888a1266e4e9068feb5a1373c5dc806108acfd476af6b77153a5222e0ce624e06bf56ef1cca69f7fccb3e63c6c288e3c22ab86ae0309ef53490143e96da053b686a0d876ee3d675732be2c2ab87cabb2b089f8b6be38e9705ccc421c4ab153dbf16f3997e3f1b40fddfdee401139155cc3bcde2aa0667c99bdc381415e4e8395f0fa7b3ae0e5a73e35f66c8a327705637698578ed707f3bf1463acb68891a36857ed96cf5f21230b2026324359cc06244bea558d827b80f79eee48ec9aa55bf29ee872986b1320abaf5bf6b36836c7eaba504e8ab6dcb070d6e55616932a69f0aa88825f590ca2310f0306fb7cdf97961048174999c18ef0cbea0216c2944f43cfceb998a9fa2977815b2043aefc4a5565a88b0c41368dc47ab881d2d8ae676738415a73b0efe904964c4ee25ba0addbacb3f41870ef0ab91150d3363bb5f938b60b3a6badee17da834c3a885a32cd8f1cff4fe177065554f41c537f57f8360fe804701fc8ae7b2410bbaafa5bf8a735f263ab5fa9e3f786a188b2e5e187fb33486f98b6dc251ce723ea1b91a3b93d9026102467d98e3c2f144b2bffd60b493d986b84947c4d0b26c02923e40e9177339abfa48aec841cd6e086d5bed7339ad84a6470851fd5cf5ec50b999041092d6daa210e47c746f62d5eb4c00e84c5a92c0a1fc7a488739fe3adbb71473b4557fb4a12fac2e9c33afec4404d3d60efda9b21c307378dae06f8485d7f48591ce6e37bd43b14a44497b08ea071a941c88285abfbf6a2176adfdf36db642312a7422e17d9a9dd995406ef6927d4f8276f0e400209460ef1707f0998562bc1e25ba7696e4c0886e80f5815cb8f1e6e4435f8c4bbe9618f9cd9c5e2ee434f5d81abaed382e5ee08f18c7d491311e51b447305f2f7d0fc178ed8e05ea525a7b311e6287ca879ac17d6d6629dd5244baed1842ef2f92ba4c1121772e83a61f913158eab6dc3f43575ce2ba434e19e9dcb61668a9c0392f03dfc736827ccd0dad0cfbb16746e9d79ffd782c31614be641d970dce41d2238d8bcd06d9c31eaf3ed7798c6bed444361eaa29a24716955fb7d8a46ea5e5dd0d7369d99969d864e99a8bfcdd591e32166f687f163a3b01fb97e1552b4f40a243b0b6275a07cce9edf93e2b380822c63865aa6f1ca8f9eaf3ce0053fcb8a3f201ee750a24536baed662979bbd13c639ef81dad9ade1bfff5b54d89d3f92920e2c29913a4038b16926c9152857fc7ed4c74af5eee07e716a9f1fba3260a17d37d2101e0f777bca6e399f8d34227bebfa76c0b5acfbf0ad5b22c37f1cef28e23eb20bcf213f0ba8bede81b9a855f356152ab72aaac498b74d4c452f58d0b88e20704a4472f0b7f2ba7bec55cf0510cc09cc8111b8b12b87a8af18ebe301fbcaa07e8f1bc2cab769334bdc639b9843161461eac15bc9c80000e32be985108c7b45eebee8acbceff65b52cad542aac52626585b250c95d08292108f7d612c273f34ad0edb0ef3d1047d8cf9ab52d4ea08074776783b84fe29f0c202dbe090af676058bf6bb1d227aea4b7f1c5f08ab64099e5499b2f2d34cb5638104aca898e3915aeaeeab1ed10942751e755cce70605b0d3bcc65db4d5c0cbb25fbf8ed83850a1f3183430ebdea232afd14337fb123a2087ec3d5c2322eb4a195d8d9589d5378a4d787061b10d1bb57abec43e2d9c36c4e7b2405f04dcb629e57021fef2c1a8aa6ab36e779b98711d1fa53185c9842a28e708b2f814c066a88638996f098fb01dcc8687ac77c7897afdfca78e68129dfb458b05c4b174421197d911b71805a5673862f18c33810f4e7fb951ab060eca7d3b1a5f04f4d96cc63b09ddd3de8d6fcf4da5e639df75cec579463464eba92ade5926803a127fc7ae9d4b57cc604ebb350076b81c52a5c6d7257139f26fe04cff832ca5da4d2796e637655f79d9397249f672ea613ff55490bb8ad00e7be51aeb527132d2044eeb60112b48fb8ffdd2baa37061b96734291d71f29057307d3c06149925dfaf4502a42ff277496f835bafd5f98237209924e86f6999897ba32b9b830526b44a7af2b1f61fb00ade519983e93f3eb481e2792943a0da42027ef374e8713e06447bca767b9bc28f37e0700385afa391e61d00d90e2d314349d6f24f12cc26974c4218196cc18623a0d92ffb22f3f86437c182cbbdfae0d38075485a414c0c57ea4b34ec94e42bd6dc4476560672b316b2e618acbcebbeb2694d585d97685d0cbb3afdd1130d137de6b36c9992013064bb205b62f7ab521f0fff25c11b5fc380ea82ad9aa499dd37aa03053acfff8e266402756d8c07d36d5bc4775acebc197d301bed7d87fd09db7a96cbcc3baf8ea9f8908b7c6c69d9663c4894b562337d48e502609d9dc3709aa44cb3b09b81f735fc511d48c7230282ac2c9ba7cc6d6afe03ff02495f8fcd18f0e02ca99c789c99651da7262128332eb514637621af85a187c8fa219fcf4881a6d2dba360a0e22ea46011e2e254fe37f2efd87ea010524de715777218c91e9faa354fbf5250b73bef97365818e11a632aea1c29b98a30b7855be26f4392e540756810be7960cb7a3de41e7f03a03e57ff62216445899bb86f99bb3248b60de1dd9ed520fabc7db68c838c4ce8b34508bb0ad4351bb967e8c10777b2f290e536672b808e00563423e8b882a400b5feae1a0c1548447632d9ce45cfc69211143164f8264e1c0a985f121a272c3b2825a109373b7a27fa8e8172f1272f464d415b2c64100860c37102d2f9e75bda0f829d37be540950873dd05cfb9d20c91e9af38d7d489bd156220f7bb44323ac54229cda7c79ef133e27649f17854afe475bcd73b44b166de455cec19f3e50d8c32e4eacdd9d10d80756393144d8b04251769317a9eef49b0af63d9913daefa9b182b58886d1319d8ae6e0ad39e1d6d7c09e062c9bba257062b85655056b347f5fc5951db25767a05d14ab3180d4fe67f99d6fa566ffd99783b8cc48a95e77f71f21693ceb11b53e660d6d7bae6beef1418269613bd4005887b2a689fea9d0b8aed26a702794055a7155f6b384c93c9933e173719c6b4423f4f439cccb7e8151d5f17cfadfd8907f44fcc5ede6da12eadce5c4e71e7d62db34c5015734f7398c5486610fd2f513ab53cab2c2bfb5ffed441519daa946fbcc61d957f3d907b8c172d60667e9390a859560d302361046496c7bcd9d85effc160e1d5439260d0c2e521c721ade0bdcbc850dc5ab28a9df843ddbe62eefff6f3a9918e709b5103c77495118741df05cf2b51bddfe719d4838c526a254f5ca6b7ba9a0cc094b508a56ff0d63543b9ccc54049af61367d75a25ce6709f6b1c03bcfd7d47b7a330cf29d2f9ce8efc01d4813fcc3776ccc0f15743b0043c5d52261510cac6690e5e6ba5301745ce20fb83aa2da52ba309cf8b1cf8f0cef3331ac734207318d99cab8233eda7083cbe2ac0f8ca7f6499da3b36ee4fb61ee55a4c79d8660639e45dcb37eee87473d923e95237a5096f36bbbf8573444987533733537d578d474be1e2712e51d8e03e51e3479cf14799ba6ceda11c139855ec41f1406398dccfb7ecabf09e176e24c44a024cd6073182ac1f58cfb23bf6aadc375278f695709cc5e1d059dbf9cf5701aaefe8b43e5ef81b58090aa4ae41d7ac76905f6d504cbb3b8f66a6b9b74eb34de83431f7a03a9a0658627b07ba1dfd3f22f5af9fbf1c6d41d6b3bdfe6574cef264fe88085a80d9f2b011110c92486b81b3f6008d904708b98a061494c57476837ebb0f5f9445ee14585b6fd7e8245a06b4763345dcf0289b2bfbd8bd90a6e5faf749a7d5b96158028791542a38d06112f2facb7b894fad214868fc5abf2b960a6ad8371b2dbc41c52b16e50e89f22a25deccea1b28b334866bf4afc7c50ded23fb8029d9d988bce010f2cd487c2921683704e7127b0dffe8daf8021462a0068d4b42ca50c5cb96ac80ae73191c7af7af0bd228acd8dbb0b50066ca9af2b0c3fbe576fe956f8f37e498770ecb29e859f5c7c0b97e5ab51f671e80db0815aa3b74434fc7b716017aaf4e43533cf5c7d042bc3b5e4aade7df0a51e0f027c80bbefd2f5826d40d7e94ca8283ee492f9fa04b7a25a483c44b3ae79f9216b8a5607ae9f05e1fe39b95f589114942c176589d56b2d608275d0588c09f01b12e298907415370a6a907caf5a8d0f9e7eab5bebf3b63868b0d3e9631ecdc33aae40854ec63a2d77cd0093a0409bc68fa5b817d308fe2d01c76617563ea0631bb5252e875b4f870cf486304875b5248e18108eff0e9aacfa5a8fd8ac65fb25bd3b8171c7e348e095c9ff9d4aee7d57ef886c88bebcda35823d5df6d710fbdc7ded368234c98f08398ae117036cbda8441ab85e54766395b485480e552aed66d8b1eea979d420206c5342ed809f331f9aa750c8b69748ad7093eecfa7d1293ebf2eeeea810b6b41cb910635ed7ef69d7e8573c31e5bbf1261759aee31fc75eef1d91ad8cca33234ca51c2422cda19a88ceed475c31e8b7177bd45adf82b12d66f017d9f6438477989809f9b1a6005715170baf82bd82f4af747bb2d92ea1bfe874334b837e4fa503ea999df417aecc023cf44b002611d0fe34f526384aff6af39690f88707206e93a2b2d4d67cecca282dc1a1770ddd4ba03587cef40a9c6456e001b329b48c2b5ef9c139cfcd8d80024bc43582ee4b29cc5c7bcf62b4a34b0b2fbc191ac8a53e9ea1c4aa57bbfbfc5ca202857805fb6d7d89504a8e192279bbd4b3ac2a9ec2cff0c598d32f892aefe3d5c1de7dced020e0892297f947833b0821477a46e6a2019bb8c1316bf6543dad419babc2dc9066c580f3c5cf41aa0747419d410ee3acebaa3467118561cc1a20e50e468aa112a7177d68d47685f58d19115c509228c1c3a65c44fcee6a7fc83c6ab99d7656c952c2c0d9e5a2685734f1a3501703b66cc39600bec017edc40d26fd8696b72b751b1bfea966dcb4d075166e7386e76ba78ea39829be87647ed4e533e37701c5f6846694ee4d6a81350d8d2e67e8639b405bfe3a1d9c4ced6c8db7e86f2961b032c2b663557d5127228c69ce0a5cf77b6948857004263d510803f418c501acd83f1569e5c20ec55eaff2a364a62fc14c1243a78c49e7eb1a571883d584a2cb26a4341a292cb908ed5142d6d7c969ccaa7871f29aa739f7906657b076642493f6ebcd4bdc7501211861014539cd9173cf2a80a9a30b04c297810a701430538b0d4aa4594ef98c62ff89d43b1eac325e2bc4b0988548b0a4826c22445cded4cc6a5335da96f3c339800d3fcbbc0859f4f035d13438d5dc693145f4360c1f0f91801bc1b10da717fa42a41725f13380b6d20a349c4d33c1425d08864e2b99df50257005727dae94ac4f6a8f0f966351fc5b7d47d081e362440a1f8dd461cc73a2d1f342a6084bdd2542302efa964411d1116202ae4e0cc50e290e5cea8d87aa07b494d1cf8314fdf4d5db680676f06bce77739e77011774c510149c6fbfa38a8c52063cd446572b8ec4dc8f71a5386e08a55f53b0ab523a4847abc7e43086b5bdfe50042d10631842b1fa63db9a53a217e40aa27d84bc9f641a2efc138d6779e5210cbe477dd5b34b033a804be78b96125af980608df69393cbd83f722b20f2b2fa462f0d6f4252c3e451892be8d02cc1c0825d5b442199a4bfc22f262e2a1904aeb8631c7f794d939de6a3571c92ba91daf8290495ad0b24f529907b5cbb56adfeee47e35008d4f0c10df2608d1fa679a688df6ff1be7cd6633e7e0449745ecd513bd2778355f0eea6b75f4000a3b7a087fc950eca10e39e7bc6e89bcb2ad831430da37a1ec6fab6227c1a01ba8aa83530d201fa7216b04cd962b1b21a82bb47a7e31a363b34715b6b3b3ff23f6c6620be3460ab2fd2e093b05141091393312367c704a0bf1543eef068b6e9f38991dac66f1fd4da50387b099e4136b296c08c225d14af62c0fc084a48100b9938c5cff0472de42f3808866175b343ea19fdfaf32913cf6ad715f09c26368efed9b50342034108d86aef25b4ded8a18b8b4c8f56684a0fe1d3afe04e0956158b31b0a3420c22e2d48589f8a398398933f1aefa06e4f2fcd68fc60d5f426495c9b45f225747e1325d451d2d00587ad226b525e2105d4d67da17ec2f869e206a7ac6a34d6b777dab3d9b57f932af5c9f1c07b46d14dd1c7c9aea280082bb97c6912c49e634d75ebe6df6c13e9ea525ddc986f35439ec088930209308b213741b842bec6770403d8b15b96550e72429a2b2b48d73b2ab273f7146139de8b5c9326172f3ae5f58d5f6d197099a4738338c6007d707068be32876b07c684ab643c9b850d7cd321c13fe6535ad3f5bb0771cf9d8e9040d97b3c7130bfb6b74b658a1169b9e5686b652b29df367a8996e4b330160a1f6884209ffef3cb4bfd267c3a9f8986eb67293b59ae2c6e9f0e65791c662e8e8f6287cd47bdf8e9a868cc5683fe34eda17ae970fb09e56a22302de1daea74e3905136069136b1116c58011365bf18e5b7cc2723579c4a88ab19b7a1fe6049086726dcf4976cd44ea56babba182b93cf54db46167e1af13aaf9f4637fc5660284eca8cd3965f2b866d7824669f3c8d395b8f6cab85bdf61435c8df41b1f49dcb03c00f985768b7f6a7c97eec6ab31fc3c487de95b806a72ebe0b760cf306ead0a6374af57e2604f492ca3408f331c5f4557bebb57f886c07fedef9c32ff0724c38b51a6a796ed446e03f6ddbdd4b248e39925d8c52e1e40addea755803fa0b32b03f26a786863c569faf5fa399c648bbe94761230d38cdce923202df658bcda5342300d8c485a3e2878496fa64b5c60da3426ecf44ef74346b4a2109a30020fca529ebca031d1ff1c37c6e96d245067aaba18822215b9b14e07cfb613a6810fd7256ac926318d5c20e317816cc191f25db9930b03e301e86e052f108f7d6050f9f5436e03759072c4f66c47fbd7f99d8a16cade5b2586dbc6fd9cca63cfa6f01c35431fab1e07da99abb7c8ea81f1f3b7b61168eb55410c193059635997a289b95bc4f055cb48e3422786be082d3fe81ddd8c7724f509f265f88e8dc5735912f1f633256d168ae8348809ddad7c0893c244c41f9f83bc2c2bd9916a47a2ad0e0452694c01f1bd5535521cdff8756d70902cd34fb74ad0bff2a0a4be8a9ab9d0ffaccd31bbe7ebaafed0628592f5c4b268697719662b1780917d5446eba299e94e031b8e6bf5796eebf13515e5a34d1ce916a8e1c1692288f515b5239b64cf038d3e72fc20c68b4a3317b70120638d11e17e44c98578b596780ded9e13d3456329ce22cc4a5966a581347f3cb19f9d49b781caa25970a591cd04b23ae6e62d3afe692e6b29f46f12de0cc5aaa1a32e34b4633ca53587b362fa0209093f36fbe683a46464ba794ed9e03747f46aed2771a5c407f7595c3f6839fc77138e68cb32b649d5f8a603442430fa09e9d9abbb31aba1c9024a64c8c6682d3e4f150a5f4b9d877873a1984235d1271304b3baa775c4cdd6d8c0a1e579170fc5ea99ed4ffaf86a325932fcefc5ecda2b5773384b9c67bfbd7511a21290143adaa7c7d735295e680a9b113ab64e9bd15ae72769e947732a58e33479f2b184b9bed85cf766abbac27ae8a5724c641ed23ebe9b2a718cb0d1c3e23085a1ae90e9a497904cd1750ed6d5475f3c1266bff776b89b4ecb4423ebcd3512c246d209ef51994fd6e040f29639f784c2238f1d05ad5612be0bbc2285e70b44fa2b04ca409f1c221a8d07b8852817d0f21327f39bb0114d728ba005a4e8122cfc20f03836c0f41f5f8b4bb34f06ecdfc16281ebe99d9f3e34b8f744f8e7f68f36940f45e9a1b9b68d8b17048e3065882886a666301828fd9588a27719cbcdd07188524a30ccc1c8f9ec4a1def30b4bf9ceecece9e9ab3a7ce39ddbeb697f4e4e2ab8ac7d9fb149d7cd02752ac2ee2484412b0493a6fbbf434d314eb996fb58ff008ace1833cfc5b8834d899125c79f66253801d5d91bce8ab1515aaa52e3807011437b51eb8b14053e2baf4916e9fb675a810f414dd113a3029ffe153c83cfbb41af60b43949312cd97e77d2dbcba3c7f278ef916ba71ed3f041c113584654b357e79dd7e48be195620a30fd59916932129bce4ee71566f033452395ca6f74cea2d674d7756677a9a1db9fc9c91d06bfc3406ad56699454b46b8a8a4d43c850fc32b7b83853e0b01457faa4ab700bccc90415ed67e92244e43172fd7e1f0a8dc6d5425a2cf61a8ab1ec210c16566de4def8a5341c4744d386fd7676cba7a8b614cccf35d709758169dfc7c8d4f363e696c742c3b4b949b09c8239b2074c0209c27f1ccf57a246ffa3255b91313b9b0951863973434c43d03b71c25762e5a2b05074d74cbd85b40f5c783a034ca2f7c1e3e2ef116404b439166acf6714de2a947784142418f1e1e60459275dc93d785166cdad6d1d688774e9dfa59e0bc3095eedddf8abefb727524db25916a283dc10bcf1ab99c7c564086a34778ea1bd3e09d3c5e2e8cf02d3fc1e335ec3b78412d31bed7267b61ba0641fae39a0ccc697e1cb95a3d5225e6f7e9cb22922662d53775718d824bda63478a9d593e28ddfda63d2979248ecf18ee86b047f4b92a863eef48a8172802e3dacb7ccd2dd0f5ad6776435c1833e0c2e1eff78412316c3c2e92b8bc5bbc56d6d70a2add1475588eaa47e1a15863abb8f07b5c8bbe6f0e5652ed55b45be566533972e286eb3fb5cb64ad108f417d7183f19ec4e118343c57540f59ec712c44ef56102b233eb5546b9ec1a8e9eea1f26b5dbbc4afac5c0d8106eee4842f05d7653e147a9be7c7810c2b0a6238f1f4ba61127ddc523ebd68e01541b761ebaae6b3753cefa35f7ffe9fdd8582a91886a23e3cfc42b560befecc5c07e259698a1d8f015d2472b527290aaf51363c014fd756b18c616d163c9786bbe373d9e07e9c409f618eba278966a09f3949f9772c254255c297931aed9a265c692d20e32fd8198515559d7b11749630492f3a90cad732f4e6ab19d220cfea10ba1f374fd9d5f6d532ce62d7cada32c99d9808f8fa6697f3a94c264793122ffa03feaad79f379ac35924209cb4fc1200bca2d6553bd9a92d0d077e2ad1cf340e53ef5c83bbaa8c36d9a2e09e70258fc26a7c0b905354f12ab2c51f38bbf1c40c65e2ed22b8778ed52d164b4c4e48a02234ca1a43f65a6f25a55d5b1b42952706f9eb5a2dc79405cb456ad57f530d03ebaa7cf15859a01ba1cec9eff7029c5af310bd319bb6e22204f8515aa592fce3eebbfa92931fd3ab258c0bc18346f06d9d0a56195c61b7f5a58dd5378286bb7e2c4ce32c9409cdb8c214a3fa94612f371c012c5e83e3cfc065f87e03a27ec00f4435b5de8f865bc274a302ec6a808473b0b303466ae36bae92071f9343299bb06006666dd716b39cb28a06816da8344f93fd0ffb19039e30a053ea80cdc78a881730ae50d1049252e75bcbb0b5e72c532bde2725be61b47eab76b1231afe90da477974c2ecc6e0f80a38263d2b47f15ec8de44357496c9cce4b7dfacf729432d2ff712d95416574161c67ec8926a7af9c23c20e9e0ffc2c908fd120d6dc5da1622118cd98e49b0ed330088408028369a67e5cd9a40c055e342cb83410f15b074cea11928d1b963dbc1f2689ac9f74fa4d27a5cc4273cb130a86c66c76bb29c68aa5ce4761b8b3ece012e598c8f95f06266f65067db96a8d7a1ff8aac507ec9c28af3affedd3d033d61aa3af1221a664bc385dde601890bc1c359bc8c6b9fa0e3489de084cf67ca52af0215349dcbb810284f8b363b8115df6277922f1d1dcd1aa7de365bcda4e73ed5ea6b9066a98e2f3372afbfebf21b11ac98daa04f66f67e65feed614d4fad3aeb376a2fba2cd7517b71e8139ff5d550c588cb0ced6927bb18814e2d031739447218d03ad1ed8ea720fbedd968dedf50d65ff36c33a4dbb42f97615c585f537ed992a4d9f9ddcf236177357db565434d679298cb8b72dec3b1db2a43518d80fbb41b43d85880638555d664f4625b843a44b303f29660283e62a2f720438810b12eed5793e2d144d1e873c44c03dec5a99d564ac3d6a44869ae9d9775d786b4273d97459848913dfeecfae2e23cefcfa47a400ac27e6914135b4f2bbeff8e83fdb47425b8a5372733647a1d50905c5816559414bbf11a282ed793b3dc12aea60c102001c92a7b5be33ce2fc41bf0561926fcd6987f218592045ac0426316be2b44937e7c309197e01d19780d39a02c3b010caef6f26f5d01e0a54cbe3b61d24f16bf66358eff925ed848810b807b322e0ff31037fe5163919a687d3e1d7559d66108ca4e7e5d810a07222ec293538f832d43c926ad09e7f281f71289809849f34857e07e127e20c55d0071ba82c13f1d7e3530cacb505780e25c9f7d823fb19de0b116a245ffec4d34ea99e704bfde488d92f942dd738f2cbd3f5e384e032c9eea8a3cd235cf1712ab98e3c20ee2645bfbf5b0316c1bcdae9ead022b64481d64ce37a1bbf9c90b49c9bc6cb55c07ce51df1764c7e03184ab524012d136ce289a6fb8a15c48113b314ef6dfe32c76050517326246a74b080038e8d3941f0b5cd6782da7fb4e86dda204a62f49da9942ca19d703c483bf825ada5af1de7a82e8351589b3748771f9ed48e34aeed42eed22186c91eef6598df00ca9844a2c7041c6ebe9bc63eb1a91b6a49700cd545fe701362e6750e4d755f656b557b9e8a4d8bf1f019032a5a6226830b98485c1f0fd1329b9cf7ccbe3c6620f4ac2c5dfea9b5b89c704ea4130a8431f4bd6fa02cc1be30fe0609479223ee9fda764d759f2b093075bd977b0a2e4f7fbc2cf1767eaf5f23303a15113d3c501e4197efbb404319be08ce0e030eee54e33e59fe78d5076901a37bd46dc54ed329cf2e0c2af67ea99fb95b653c0f1e150c081773ca0c8d99f8f0c49b6ef6ed538d5210b13ec2a3bd85174ce90bd3addf0f0ecbb5c1a9a53547971c5179a03a10e34d297068a9cba538c27a8a022070b985dd84b94d6a1874547389e4fd31d93e57c4ae6b31152897802a5b9883d9c4415064e89737b56e33d70627f6f15996c5ce7494caf4a55c014468eec9f84294b731ff9c38daf38dbc85995a4894d2405575fe2de7091a09dded8b5b43c1c7cb716a81317fd71a1743c502c6b84decaadf21fdbbdc668c2b6454704d025aeb9c3398dfc156c5006950af70e963d541c6508b46cfc95f8e02c957378e82bb1be9c7e525d1501c4f0ef2c0371507869111a5b4782bb86dfbaccb76c78a533e7bc33e1a06e01b717fbd4feae95b7aaa5747e83ecec56e643572d886afe7ac6c07ef11929492da28c7313d337ce8d5d294886fdc8da4572e5047c44f0095f85dfe548c313f56c9b43484ebd5c9452fc57fb943af3f1893aa5574f9bdec0e686ea2359f37343913eefa3cd921f36576902980edbf71cff0856c01565220c7468015c85fe107d95834c36080d67d3f79c18ad9be238687ee3a2b665e7706b62660f7dd4f735779f81c72343bd755e8cdbeaa30fee1c31af79118b2579206fa2201b4776df802340062432e929ad4624648b05aa8bba638b1155f9edecc108d65646b153c1299e48c4f0898fca9d096502f07599ed198d079ef2a1f5769cf900c29c74261fce73b2bedfa1033beba9a4be9d2a1207ee0ae1dfbb0e0ee5cf5846b4acb583ca052876749761fc1b9d5e8e50c227703f1c24b3423dd0b8d952de9d6cfbc9732b155433bc3224ee5d5bb216a501ba10d6b35eef3c53c92aa5fa842ca0656cbe3cfdb706221e13df1d50dace07ca92540b539b9150ec59f64b0d094314f0400e3ffd83b36ef7057bf1d4f463cfea5bedeb2939f27df42197ab868c9b20c2281f273dd63d0e84dc948cb187e16c45a65b0fb5948da3bc519de12bb27b8bd1569ce1dda65ff9f2f493178f0296d11ca87fd651ea0956b43a04f9b6baedaa0e890ae84ec4794ba7113b0be9a7de46271088378254ea173063543ab891e7890db9c9a95cae5a2082cd22b0ec74059e0eab25ffbced3ecf5d3843f1db6b326bf77baf4dc3d982db339c5fc8b0fe689444a2eecb55c3dc6b3e0a6e81fb77c7850bfad8a838106b6ebcffe61f170c06956253e096e62ad7287951e5903b475b0849a89c31c0148a08455d5e156ea9705cea36e76f496613a3d05019bf41d83ac0dee90607584385e9812a74ae3490251a7c563b8a1f0afea8e0a55f33530dbf245c61ca8b5b79f08483f019d0ce62b3c9179ade5ed699112e5810a5444bd2e8a780db7ae0005e78c46fea3caa73810294d2d52d1b7a2f8b019227480e0b1bd89adfd5378bde1ecf9119d56ded4ad3416a6b0bbfb813708ce98c5e769b715686dffc4c1687f756f37b2edbd95c8f30f895ac951bbc141db005832a5c44cc7483127370d4d25c91d8727a6f33c7c71ff3472f4ed11235ebc1c43b84f682bfa08114867d49930fe9b04179c25c2bd47db25726612ec8e44d67d0c7f9922d1bbe21cef6eb2b137802b6601be77e4735f308541440cbb66d5016632b72ff1f5885efff556d3fb461fc600ffe037f4b4ffae3da2248645cbe1fffe323de6e32f4a096435924e833dfb4760ee711c6d40174067cddd5ffe921359743785f8065dada7cec548172865d7674e807b13d733ce90f5bdea5f2173b64a10706c1bc2f73118648a0b2a6da692d3c74836030041f2ea4a3ae0acb9f85968ee885656e1af41e5dfacba30093d39b10e6fd09a2b087b5d1087b4ef26c1376d2b85f98f15a77460f579cd5bc6540724ac2710abc8176f9bc0ac6ff6ec90998fa2e7ae445a24a8c37c2b5b45b35ddd98d6a886a6c373b8e6a54d28bd4965c56dcd7072a8d15be92b0a79729edc6f9dfb6e599e44e0c4915cc5867b3c7605837199e307da175a9795c6813d0d04ba34f29e5f8d10cd410fe60e255dac298f7ac5d50f356f44f77963a45c7488505c19bec4ff16863be1de19c6ddbeae9caf02491c099ba90419e6836f812e49eb9a13dcd8feb43aed62fdefc3d5d6e939b258b00041ba0fc26e3f17c153ecb58b135c2ad6d02d4d177dc06baf50483560267edfc4c40bf5b4fc4fed6aef910a5ae719a26683895dca1983e92ba0fa48cd2767fe4066cd5ec0bb4f1a400142ee1b3ca9a4cadf7a0ffff5eeeecdf25fe59ddb41c045cf73fe64f9d8b129f3044693c7288547ad3de0bcc27045ebfdd9dfd9aa63e57df278d53608f05f3ed4051faf1fe9d8313bdc909cd356821b75c4db091fbdca7024f74f6c1664f1f241f0477b35e5052a1a10dd2fa90f79b22a1d0b93b8ade6a63c77d579ffd0e09c15088a8075296ad51ae5cb51ecefd1d83e2b75c7ab6813db1a9f8058886bfb7266c9fbeb753f765082df60ed0b17ae6eb2c49b5d4fef742b2ded5620f82af66626d791df3b0bbcd9db3106d13a6fe001764e99655b694251e2274a57545d9287791a441f202315841617781e733224dc8fbf74923af0ce5aa0aeac1f7b2e7ac200a9e5a24b9d97ce889f35157a8d8fe9c064f2d0ebca6ddfb5155ef0cb042f18b0c840bfb0869a5299bd0082196d7dd0d59862ad3ae40faaf932e7e15c2355329e39e87938d0f502e30dcd394ea774e9107bf9f598d456658ecd209f5bdc5e3f653be2fee7fa3efa23a091c58a2392a053f39019261b2f038768278bcce4bf54883524d9ed775cb50fdc6a4afc82845b0a576b7a42d853fdb69aa2e5756ce9c57006234612fdc0ae5f29c35c5a1f528c4edfd62d0044ff7c6c30f457c77d4326094896de4c153e9c0a27114e3a773d425952d319a5c84f50be8fe3a823682197b22b0ccf9baf743545e46e2873470c2406b2b6606ba28726f98eac420f980b9623296149ef6401cc3220a5bf6a1b0bcfad3449a5987bad56312f64c484f247d12fda6a72e00be90e5a34803f4365a53d1d4bcc5c55ada765f82d59c8bba0e09729b28d60c2e57a14a0de999764404cc5dfc1cb2ba3f4411b54368782eac1927f5d5dde3ad674fd666c453b97a76c09806c1870b3406baeb0b6d5a4ed6e34f3a95ed69b93907970feeb1a9b58200ead013502e3180c8ebb24c21d6bcbd0775781082756acc35365bbbf17af65d8a717f7821532209db874e85f8322ebf01a74b798706560703f5b2b37edf43a67ac4d510f1188733656c3b211325c42783937e7f0507cc98521a76088b621d01c31fc5f1ae3d8be0e6a16fd9c6637154fb099d264a68960d9e34b6fcafeaff474b6691675c5060909fb5f625a248d33eb35bf7edc72bea2080c70f4004e66dbeec45bee6c01cf95f813cb9b8eeb91e7562ad7d53b1b8caaa9a8aae94cd18903430fab9df066056c0d4cacca11498ed4cab478c2d6bf999921d2251dcbf1f523f185bb86ca1002ba37b64de5464765e7dcb79a700f79f3cd75542cd9eb942789f260b40ca872f8f294997ad12bb01c1cbed55532f176157948729455c96239d6b5350f6149a3f1d7e6fd7fffed36400efc4c32cfb5eb53edfb9c6c0a9f146cb1521f520f08e5b96b6acf9f624782658be2bec7c2a26c7e0c7dac22c53bf532f649019ee870e24ceb78ecdc8873821cce98da0aabf423b3dc4408b7dabda2bb6c0286dcb6d8efc111ade62eeab90380e1f9f9ac03db2fac0208c2bb6dbaefcedfb5c50eed77568e7e7acffbc2c332608805e31f4ba9d3166e6ec4e64100d1341256e35dd18aeb83e73405e00190d53292fb5be179738027be8979fe1da2818a8d4f96406fd4d905d7c6502b5dde390923b0f6a682bd1ad33add7f49ba7ee087ce16db7bded565f95bcb7b7d715d7f4bc72028d098e832250b4631b78f4055a37ec2057823c5a3fd7a38a535e148f13a1d336da09697e6af1410a4a2606264fcdbae6cc748ca6bc89190c12a7d410909cd8c201c205c244e81f7e1126c6e1f140fbceefa720ed4847fdf18843055251ccfa22f8344887eb036a170dfc5e70395196481c4f2d0c57c7c3537d9a2ed32405d34edb92937335733de3454ced0835964004004a3f6ec93a57f22a5483a7327cf9ba5c147736a2a059760da4fd5786bfebbebc7303b389ead6904364f523affb90bb7d787a2d5f4b43430fe7f149ebe1991f9f9ac53e18afc5b955f0e021bc1338e849c0de9b7bda2a63ee6fe5510c4a69dc1b88403c1a15900d474c89553020f020a3be2e9727ffb1c645e0d708d82ca6097246d1dcd0ecd705ba755708737311bf3ced69ca805bcf8c658c228a3667a799516882c6f09768393d43e911de1fd4b934c3fdbaef809e46deb7b43b572222abf64293e0b387705ac39907a3246997739b5fff7e18fa58e001cca65d279b9dc76b20daf40c27f7735a147d323e3f841d890602bbae124b48f07f8a26989305cc09f125fba1357a9dbebe2de48d92f68bea59c5321423aa342da1fecafa77ae68bca3f0b99960922fec46850b44f282ff75b4bd2afe4c1da517d7fcebc8d61a8b5cc6c3f38a93ea39f28bb3532e4be7a8ceea325a268435464cdb6f9fc36e7a277c5b9a619e92b3b2e13353e25b12357275db463587a936a16aad58ce62da401b3e78a68c074725312c1e77edb921c6a73b01d37318ac6ef8634aed2e869a6f4912e2ac4c475a9cb6eac935f7d0820ecac9344fc9534616ff8bc1d78cd401b40e9e1ade99c20b49fedb1145659f3ee99d4f56d990717fda16473b3b02438ec1cedac9e873d97d3934d3571ae034ed1a4a04c7d965c8dec34532d6e2c92afd20d8b80cc5678d239b561b2a1822005f3920f84aa83c3225035966199232f2bfd92bf43f36d15d038c0b09c9a51fa4982c2060615f50c00b576aa2cbeea2ddf7f8ca0862e2352ea7f8884c11be06270515fbfd8a62c27fb3c64281118f18362f33e13eb6507cab7f0a7d5ded0c42c5ef5ecddc8fa746a823479b7a14ee86a2ff481f31bbb0b4d5da3e992aba9d7eae56d511c0a3113a3f39e199dbc0fd5789a4c1aed256280ea8299c517e043e95e29ddc00545024f3ab4c10c5917d571266549605dff5fc5be042bb6e0c017ee2bbdba6574ec379db3dad2e8712cfaaf575cac43174c185cc028662e68fed47d30374df08a4e99a643759739d2e6fa5d4a1ebaadfa89921f6d6d7e3345632c9acd22036f4446f7d6b6f487881210e51671e601f92674694c6b32ef0e4caa639311914673915164cdc446046437471a0b56fc860b979b6ff8261b0a363b14246011ff4390ad9045296573790eb5f43aef252cfe95b5a31a1019e68117526b8b7658d5b6e17558cee120f8700e9ac5ba36f2a0d8645dc264010c3b8a33d9340c53678b6069cd4999c81b8c53f8ad280c5b28ba33bed153401d6812949f6479b2d711561f59b64abfe741da366522f7d29b8859fefe1313790a752f7c501d33d3360adb3e46131df2ad9320f5e4754fb8bd4e913cec040c70dd221592e771b9f47e9901bc3e12f77fa8a0128b67e9fcad1ab9f1e71aa924abbb12e85a0fe41e2a0f7e19d6b9eeb5d708c375052a1df16c73ed0e2e0f7fd84834a6964c5835d17addc03f7a3abf5d68e3e2a0f0db6b2c4bbe74251b1c7c97f31a6a8190521f00ec6cf830b51a038498571635e4024141d8264e7c7f1d402f483c0f8fbdbe8c638c9c7d0e7b158881330ecf340395d3bb7eb4a5906c19b533dfad61a9c3378e68424268ee4abb2abb2c0d08dde3cf4b471a9822c431ba0eee168f9a5165b0540b813d7d46c5d99bcd7b628a756b2807b15c4c5b299383194781cba81e34ec18300427af4f46eabf49bd86e888ddcc91191ae3f33f81761fe734b2818afef82010372581ac8b13a3a8c2313f5ff6f9dcfc0b52103a1fa57ee7bf13b2415bf3b0b0d42281378148e387e688a97616b78e3fbf0867ea84a497370b54289b68c4d6b1d197f2f9c6fe76fcc54df5a81d9eb7a21d40603a598f0fabe659b63b40dc74d45a6d029332dc3211aae06dad2c4be3f7404048a4762d30be2b4137a258c6161a8f2bfd29a158346c648631d5894d58d2f8efaa8e07e7d00a968c027ec40b6b7fd1c2f1b1417aeb4df8ad4dba817f68098fde666b3bec38d61ed4b74c26ed335f7f68cf36be6cbb998f10f5d195837d7d91fd71b9825f5de96ad0b940d6bf9a98b46d08cdb00596d3dd4f17518de2c8171b972002acc4d639b39280cbfb559a632b5074476e28797174a1349abc5bef9a4404039180323747e89a8da4de2b1ec74df9b2a06366e17947c0d966bdd2c70a9715cff0690329645f269294fcdc831e4bf2379791b068b4546365cf0acd699b1b5eb7e51c1a10ee72bd493ac5d05aa9759af9e781947f98db7906dad373137358de4785d546fb4c95e3e68168da8f0c440ad2aa860c0527a8f3869b9df0f04ae9e88994d9313f58a221a60c4886d73e70d9bee39d6ea709055e12ce023b15cc81ee1b4560baad8dbc5377d9edefcc7ca46e1759695ce54974cb184bcb0fa669d0034e44e004b87300674b02fb645cdcd227499ba8a48e3e44becb24c626e80670fb54822f89caaad1c5e43117d9851550dde41867f069c6f937a24ba99ada3367dc54d4ef1c2d183d63291a90a78cd92c87d9f19d3ae6e1dfafd69cb07d4728da9e34bbfdc9a389babb0d6f157f6d0dfa7b9ed73ca00d28ed378304c9b366f4c866539a5b84acab9de71e167cf7dbbfb8d9a068ed32b60c47909b6e2b45ea971a9e5a1ac74c2b33941def6eea2484f085db24dc46d24d6065bd69def908ba87c3dc13967fc1f5de7390f4c35b81727272df5f9c6d6d421817c08fd98e93981ee5532d3e8b7bf2571e8d14616c4415cbeeb2b58e85649a611a019a54928fd778bdc6309109fa9e29a6a4d56fefcc73aa27c7e5232bf79842b0f59667081dc88c2849c8cbeb8e33a02b43eacb40fe19265ae11afa5037aab9a9362737d8452a1b53f3a81d7ccdbf4629bf95f5f945919962ad3677b7a8486d28caea667989b05044b887374f71a80dd1878ee910d6c52649b40b237affa2f3a9dde64b1b4160b1d5e6525a916e0a8005ec7d16e7c4cefe47fe79f4b694acec9a0fa512dc487f5b2fc71626f12d65cd4b2ed6bfec8b9e9cf95e372dde18e725524948d452018fe9812114bef446d419b9e5a9a7ae7fd687a4d75d37fd2b9436cdfacc9cd2d53549a8eeeae0b4ce3b4f1beaf3fe9fd5e7e8897464373267ce811167e6d9f6971e68a2353da8b622ecbcd37d7ae242f0c6c1585862cef39d1cd77b53dc7f34e4b4e57f52c239161607fd2c29628adbaef6426b1149a4aa75bb05a212803bb2aed21c0426395ba5697296c93f8f0dc24554d081b8c4ba28f3f0ec0d70f3cd67f3c183358082efbc632c13228ca62c68d50919755c4f57138f763bfe5565a1a1f4a7973c12bf0575942f15d240b3848c3b66cbba81537937eccb57e63d93d0a0bc228d427649db5e1f810fb38d82522cf87992243ca9aaae9c1c7b1a8154efa0d8117944018abfada4b70f053b98fc0bb75caf4b44161304213ad0ed6dc6b5dfb6f6afde9bd7ffa67ca475546737abf8ce31951880029a58581d40294cef9a8bfc2226180dc0bc218bf7ccb788d67b48836d250e6cba6fff491683d28bfbe5edef375c6fc89008e822668455a2777e9dd20fef8fa36ce818968c0e0e7d607e518cf6f330e61dfdfc3414fdc1afa0cb6e0d68d001cd32e989798e5ac2a6d277f9513ae4d52de7a484ec0b348736a4b15bdb288785ac644327960cd35b61b5b5e313fde177e5d74ac115e595e70a45d0bf18be4c3425dac8714c4e9d0e37e4ed301b2cd5e712ef071d6c2344bcc1531a227e342fd460b4088ced235c791862ea85eac8681072400e6076f7ea732e8d8d340275a96e1501de550847ac044e31ed0bfc8be10570a398e9c9adf07bbcf410b88440c17a4dfa18f3fdb48b0bd6c56d2e56be1758ab71ae1a72673e27b462da933c72151d2eb7e4848ef09483fa3a0163fb0b314c43679cba5f378f0e6fc56f64057823b6eced46b4ec56ec170131e1607b20d4500182ba68aeccd2cc9630bcdea660f6bc729e1244f48597f715d5f72e6f900c249de056856b78f1c89c74bc3408e11f4d5e42519e6b7b4ad3fc7abe1ee811ecbd0cee038e8cfb8296a188a410fb0baa73a40f614422e20291cc0a1e6ba61f6baf2707080df4f79966bdcb3b555f488fb58e294df376a240137c4bd7d8853d0b932c9fbac23df38f2be99a17b351f9bcc0c8961cb10fedf95890bba9db27304a9aeae383c71880ed2d5429d67cd7013480dd4ba81de5fcffcbd143b758b8948d9920a3d4e6e4d70f6b43458ec5c0994925a1073c8a49cdc07829597562593994e737d1ac61df02d678ec8ea899c94b58c6bc90b4d7ed0b3762b17ec876a65a65930b768292b7953792b5d8fab7e9a1be0d7c1ef8073b8413ee7b6e8bd0bc3a5a7f857bf2f09b445fa56d0015d32805a485181293a19cffa2ec07372d2e3fcaa32aa17f03aef8465ab84a8c0a829bdfaa6ac32aa3089d33e7c8d517771e2ae251a2c7ca50e0d126e198a56e12eee62d16f07ca88b380b2293082c7781bff7f0f6b216d72b0a1b294d664c9b29b6b49d4bae48030536057b60836208b5209f1b2ecfc2976dece375d18d112923f5cc05217613d6c34379deed5cd3881d419f663ddffbabad3ecc3c4e70e20efa80fe3ccfe6b72798a54fc7e419f786f3ec587994e3ff824b69ab21524e1d52fe583fe0a7e18ff13c004dd95b563b70f4bd6fd7c561420137fe78c467b7c0bfad030862e06ab6ded1b1d9dc36cfa810cd822d47b2627fb981f4da4cedb77a5714c9b9e5d62457c09daaeab00a5c32314a88f7673b337d2f5c888e08ccff826bc78a0fcc5eea12e81efda1bb0bd9b99a35b43514052f8f42d39b8142708fd6b0a0bb0486106220c83e1865ae11d571eda41ab47d2970134d0da96c6a3be5b3afd170efe24affc5e05b581e36e5949f660f8cebb5e6e2215897ab7408995602047bd1c26ada9632ac85d01ef9761413d31cce628515ee47b48fbd50b8f4ad9dd9781b0d3d4737c1699b78beb6eee6893d5d0f50f16b27cbc38b698544771bbad0c319117f02c7aa8b9b10d166cf2338f9e24644ed30025021659d877e64a20019e3b9c40c1f82fe83422bdb493f13612c5c97701e33128426a7ab4e910f08dcf624922a62a7a9cc09ff3bc042efe35d7c2378e65fdf9ab49ea6b4eb47108dd09899560cc4c5bd30838da0c37decf9bc2870f082223ce2897b9bd9e2df619df031e9814787961bdc410f3c3901f730d5b5398c0769568c9dc1752bd8abbb7c14a973caf6feaba27ae68080256bbe996349d8f8f48ec06debf78d88a79b18f1fe029401c810a31d910627132e3a0a0374fb215e1166dd82c73b88c76923f6ac036d0e1280f1c0b1ef9ffdbfa8eaafa871115f9ca2ae5b058aff94e48c6871de2ced19b9dd1a4e14e2c407b51894a7e21f8b732f2d1041085b3cc96be519881055abf9e5df8923be7386c86e9e82c5f9864709f47e6940906b7a99e7d7bc005032dcc7958e615b67a4e71170fcd12d38e46a4baf966d1842b76eb77c0991715f7e7d89b6de8d1b7db8374391826174bac900284cbdcf65bff785b815de974150911e974c101a2bbdba514737f7ac67c237f9eec57f94a78f92d122823d9730a4864a36776951c3882\n");
        assertTrue(Hex.toHexString(s), Arrays.areEqual(expected, s));

        sig = Signature.getInstance("SLH-DSA", "BC");

        sig.initVerify(kp.getPublic());

        sig.update(msg, 0, msg.length);

        assertTrue(sig.verify(s));
    }

    // TODO
    /*
    public void testSphincsDeterministicSigSHA2()
        throws Exception
    {
        SecureRandom random = new FixedSecureRandom(Hex.decode("7C9935A0B07694AA0C6D10E4DB6B1ADD2FD81A25CCB148032DCD739936737F2DB505D7CFAD1B497499323C8686325E4711E95F8A383854BA16A5DD3E25FF71D3"
            + "061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1"));
        byte[] msg = Hex.decode("D81C4D8D734FCBFBEADE3D3F8A039FAA2A2C9957E835AD55B22E75BF57BB556AC8");

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("SLH-DSA", "BC");

        kpg.initialize(SLHDSAParameterSpec.slh_dsa_sha2_128f, random);

        KeyPair kp = kpg.generateKeyPair();

        Signature sig = Signature.getInstance("SLH-DSA", "BC");

        sig.initSign(kp.getPrivate());

        sig.update(msg, 0, msg.length);

        byte[] s = sig.sign();

        byte[] expected = Hex.decode("e8a1883716841afecbd6f9bd8648bbf86ab3badcb227b624633d51913eb337e07b68834818c993532f90581ff8e26477449fc5f0fb37c9d8462bee7d3f5825316afbd4c9a2a266d71d7f8ba4db064c665e02e7aa0d1ba9bac5d0ac0934db69fa09fc85234a701887cfc0af912c7b5d3186c0489e593fff2e9b5c79a0a77ac312aac4049d29ad57db8e86cec1c1264e819c5083bd03b4ac44b94be97756e2e4b491947a2103b371c1b54940bba71cbb7f9bbcc8eb90dac25795d1148fdbdc3cacef7945bf9744c966cb73cde15b98721440d2fce6294e77c39bb2cc37738bb2c2ec45a8d64a7fdda31c2a5f38e9cf17afe942470f1227e05b907ada0564ff9cc0e1154b1459f4a4b21485d901582c2cabd443635262c6a899e774e27d7428d980c77e2d42c15bf9f45b702462dce170042b696598fa8a850beed7517f717cb48fc98c8634296e3b8572284717fa5248eaca46c8b20670c31347b919d6569d351e4ba30595a5adbf887c8e971aed2dcceb4593ad18db1e5f9226ae82366e5c99c44e22ea292912d00aa6c53670bf6ed0e969c56a95015b8c5e0641885b4ceaf45bd2d90d5b93f5b0f63a8798a572935e2300319aa40e6435441b611149750638e3894e66e7c3ffc6a4f1cb37456a7c82b05e2b6d16f8365f05391f25539b835159ba9b775e85abda82d16d6b7b626f76bd2e98cb31b82ba8f18f0309c41677c2b4f5e822f255dffe17d21e7ecd421cecdb7e6a3f88e4d76fa0eeb3d7e9677c0c983223d029a025a147399ce72a13572edb7d2689b361993a06492df19fc5391a1e6e89d4d81cb5c3eaf1396941f9a51b8897cdf725ae8669f2b4b9435277ba13899a8f1805b77fddf5bd6b2d6dddf02a185d10f3196c571ab246bb8e3e1fc97b0b0b4e1c3e2186f6839b615c210613c4c3c7fd922d1907fedf6631bf3d1ca99914ad5c9fd34ca51ae4093e2a925c6a967b2c2e8c97fdf73d8dc3c6fb36ae587e50e0b31455f618811162c30ecbe1e2528d325a8c75afb13cceff548863c535bb6f72779fc150b74d33b4f98f7dca144fa554318cf48863fdaf16c73ab14e5c00580ff227803b1c8c383713bffb6144ae7b02f0cc1113fe2f57b72b93edc1e0c363ad4745e5a96bc61b2ebfe5fe1fe6008e734fa9382c0b818834e22611433ca213cf090c5af84a318cdfd038d8cf6936479d5b35dacc30be7b92e13920c0f80e5a6365ffa3b0c35ee637a4e861817b10b6c6b8f6532124c45289ddd027365e86e76b57ac42b6c15abff1b0426d1456299f9585b16aa0301d333837e751db28c0e3ef942d577655b70219353954384b649dbb4cfd8754d80250fe9ed859ab8d51e6c663ab32bc6c5972620214f3e08b3275829e1e97a19e2795ee39a43e56c1adab144951ef5b1cc1512eb250625d7bc18165a20e588f03075a524c0cac05c5da810632680e05516815c5b32262eb5b3b54851477edd61ce14d3238c3d02f4518d809887a49d148e84cdf7e50e0c06d82b41e152a5151a576c69fbc812c327d440b41edb75c02ab444ebc7da11143e440cfbda9c6c7916264b95692029e4c1bcbe56c55bcb2af6530131147de4a1b384b46179bce044dc104a3131ade59e4a1556e665d6ae0ba1bfcb433215d6b9d5be7b023045b0b49490685808b1a545577abc9abfd069aacd33863c2f5d0daf41b4c5af5224803f248356ca7c1269315c1bc4cf8256cda2e1dd2b1f227b7032ac29acf80732120ea3f9aa07945b602810e8aeafccea49d32e5050f248f72f3fc839962ae0e1443b46b586fbb48a2aae82cca180d580312f918ed208a2b6a493cd63b881a75e321a5622bf47314877bcdc9474019b5c64152e003d857b9eac87b3ea6c8f378592078326a4cb16d66caae17694b306ec4965f85a064175763ac9d4b457be3609188ccbeea07087f5051c66b5ca51fd88fb91a1dcc3f93ebb7840645283595fd3c4148bd62e8dcf0c5da4b89492222106228717ec8b473f7505defcf6da41c8e31965c76a067604da9f031f0b34235d7ef587748ba03cac0f104ebd1d29a44e0ac96c85359550a115aed8a8f15536032b6fbf4ac8239eb94391b2f66d7f001114457a938e5877f0eae1ad36ff6a853d96ebd8d5e44391e83a940fe538dfe2caaebcf7b6110cf4e51617f3619480c3396d7c9d2af597e113acdd794cf81de24a21285f4ca9bf56df99e02587bf89674e7db2a1a06cbc217940fda6248befcb93a3f947234e59ab6b03333932c015dba3c88092f362d0baac5c5b9f2d9d5a829dd3ad4644e0cde89d4d8df4d547187d66179f7b350112c4c004e6afc97fc97793530be06c13737386ba92b13cce0c0b6cb6b0aa0d82000d674d1998f05b271643ba85f7da6304dbb6f530d2c80c40c3e2f925b87d32603e377b3a9ac486e0f0186c191f4648fbb8e230f192185498e3e09e82d321a9a6058c553419e21c3ddbf147c2ed88f99398a7eba4db3a7ea39b45693285c4d6d6c8a1eb8e7bc0ed937838afd59d003d69623f6cc6740f2a7b1808073fc7638960d649256026d9b714d903719ac7959405eed2a22e4a9d72e33ab6f0aa5d07be4783b4ddf36af1b4d4c78585cfce80738b9c1225660f5e16d9de5c9ac285d24db80c9680525d419b626435fafebbb683c9b36bdc1cfc185cfe87b6ae93a14e3d63db6688f300154f288484c07c97d82f438fb9281afe6254170ea6d8037108d8984e88872f1c9072eaa46ed6ba426282ddf6365f010323e176e11309a3d80be22f8aba5cf93dbff8658665a9d2e3b428e05218d9da73aa0324f9500732920cb278bce651e21816c61376d1cf6d2899f02423b33be6a8217c217dc42b1f97abf8f63ebfc367b4fbf0f158a32cb2aac06616446a9773f6501692cbbab803074b5c026cb3b8ab7f48d6e5818e668198cc958b8acfd6469e8b835aca0e5bfa5a8f301ffdea73c8693f6c656cfa411e7efab0842da13aa7132db26176c792fd1a99c79551ab99482be3674bd2e37fcd8e0701f2a9cc801b56e717c8186cae04287fc741296e97c5563c4b64e7d36b76cfb41ff3ef32c5c88a4dc09ff91a215d157fcae725f7da8801e72086e3f063529eac6a11d4845c1eb0bd5845801cf9cc35deb27d7bdbb67055f641b9f4bfaacc0af6124853cee6cc3a858c1b102fde6da1d245390d6a6db8492b1142fc09b90d8c985ddd2a82e9e79355a070eccdcf125ba45a2543d473cab41cd9ec464b77fd57c54dd5b346f954b1c2acd37841f29f9b7dfa767fd029bddfbd0cd3aa285540a3943c6d1018f4cf87fd7c17fbbc65016d5668d2b90e01f3176218160ef5241caaf3bbd747c81da560d1debe3dc258197740839f93ca6eb41e7e635340e9de07aac1b24c5f48182d0bdee3672097d2ae48960224038c8fd710845d0927f647dbe09062c586842d31e1018950a3e16ea5d209402367badae58d2344d169cdc05f5a47f86903d18902ef3bed7d3deea961bc2e8e7019d77005ff88be637ed0977354b26ca98a7c0dd436af45341626540e050d7f4f03b703f254e32bd9a3d2f93997052732773c2274cd1a26da956105c5fa59dbfb002efbc28d3cca08f91f0fa76289a1f68decc6f943cad337f710e26e8287ced6a35b3c4a5b2598162fe2412cc2d44b49948f383403c23ec22c585e95f91063202da0755205bb592fbd345e10bf1b545187a7c14aa88106bfc37bc05dafa17f0e2bb8edc2179b3093bb1cd955beb621d2e222b39af3cc1ed26c7067012b4fdea539c983e1481b70dea56506a3ad912257cd7cd58da4cacfd4370a0dd292c319f23ee3ead9695bfe91c7e83bd846bc186b1703061a9d4a69eb961ba06415d4dfaf2cfe839337a6efa0e6b4f4a23c700f678e517a64e8a0c1eb28c6044440f203d9eac89c8b7d406a076bcabdce36195119001022e640155df8ef46241ea50204df095b96deeb70c2306cea56794e9729b3fe27e114a95344ad4d033175decb92e0ac3a88a16e5ba32f8c94853764fc7aeb16591cd3cdeb84b24ef6827a341355e7efe0ef360991a20e6ae77a04d66bee1da160f14ceeadabb7844e3baec99a057202d80f41c01c6f59d6affe7497b137f93e377e3b9f6df995df70480098c46a85e5b9d9b3fb7d4b7c6f4c72e1ea8fc442f92d4d74b41ce026aa5ecfac54ca2b4f45995799330082e0b558f18c5e31e698c67f2e82dca0ed3540f8493f8176b9163633481d4a444ce792b1b5b7c1f390853aad64979678de457086d7b7a0c0230ee0d0c269322812d5e7dc8e6e1e03dc0c977e81a6ac37b328af654ab070c6b073e3d0194046e9e91898e8459b90faba6e0c5a14a764d919db650c798aaf27ef1ef87a62b3b5d0b69a5abd7ea8e12e19a74754deadbcd82867ee271340c0687e7091091585e1163da7ac9655c91a62da7850478d2283fb6946306834f2e56025d863044b564818de7b43a7d895bc3b260f4d8c55fdcb09d8d01d11631e7409e3dffa027be768340e5a1a71c518396906b1ae32b44b08f6c0b54ca53c7e73375713656815e503a799205ef9b6753d177794c753ec2a067421a13272d09131fe37d212c19790d707c327146823e7442b56bca450f3de89888637e0dc249c2e42c6d6d47a6a49a27dad3aa5b543a0130d7d34f6310bbf8aca6e514be50e2cadc80a7133545d56bfe06a017191e5dd5ed598ba52bee9752896c65fcd4bcb9de79f7a89d781dd47601df7445e23104f2d7f9341d6c1e833247b1f5b56721255d2616e6edf75aee159735f15a70a170dcced4f0d029800b6462fe50379eec7119530650b4606ddd7721e568e52a934ea14565168c45cc0b4e540149badcdc1f70e3079f2adfc8ffa44333c88c5e875e64377780a23573a6f009d8f8d8bd3a2ec814f9a5636f19dedd93b0ab1f70a4b6666520d7b060925c95c2725ee065f52fd09b2f3b2b89201de0174ec755680cbba3e5828298a054bcdefa112aa739c554f847069ec6f4bc30c099c67eb930a68d20a01e5c68d12b9f1b1f3c557fc9ddbe6083aaa884880c95721c85ab22cbb5980bba49c708edeac69a95f7e0e70c9a75fe011411a1ee730f2f6699ae74708608ce6f33435efa0b31379f6c8bc2494dbe7145eb70f6d4d46f8d7827071c49d55c487f9fbfe1a56a7db761cf3d314205a18866b872aa8b9f4b68a930dca64e8fc294b6d59eefe25cfc1008689c78a1e90bca877ce9f46aa05f81e66a415092ef9bafff8d4732b12976b925bd83439e547e3df349eaac385d674bb2672e23290e5db0784ebabb24bed7831e9965c2db3dc8db4ca4c3525b3b132439fd0de7fd1480e2e697c2165e1a27b646898c1af610276c6f58fbc84104a345783be38749ae3f968c980e368b6c7943fcd5a3fdff44f4a44ee55cfd7f94d0eac235dad9296e979f32d5ee4fd624aaca794bf5cc30584e505382b852b880f6aff7da68d4c7970dab6d5510036bb453a7462d7cef59fa78d03de0ba69b266685dc2f17ce8e8a6c23e465175b352c977eacd5fc611d55a03dbb46a831e5016ea28329373d40cba6414193641f75e27a5099676670634008678c3b5d1f14e688a1196b08e4dd855611e56fb74146876ee12b6d7992dc34bfaf68462322e0f169e61b127c00b9c8817cdb59bc675387f671e913d64662128134932a50d8cb6f49a13646fcb10e2c3f1c8c517c5296d1285660549d1bc0ade7c03354749ea811002a9cf526100e264a6f9506c563211e56a811d8ee8eb8e2e917512d9bd38c0c1f51c6968cdb10b9d526d19f4762636bfd9353f904cee43d28b31f6a65266f46e0af9e7882aeed238450a985b493bcaceaf8eef545c93eb6b7a264dc278fd621c338f7dceddd29f68c20625619374410db7d45563e2d90341c475a5df5a5f8dccf3c648072e205adba8327eb36b9d2f0e7dc5ae59933063ef105538974bd47f11379566342c07461f6fce54bd2ddae8004824e93eb63cbe950663d88c31b9cf20e4abfdc1892405b4879cb32ce9c6eee7f93da5e7955d4c04b04cd13bb4ff3f13ee1ced444b80c92bd18d8c122f43020bb423a15142932bf522d9df402a29087bca975a852865ae27a9989a5921ad4345cb4a64f7e9f6aedb0217604a11b3eab8b4adaf2b9f527fc108b3a6d94bf6d0ecc63a237a70489041d1d499316396d67b5b8c73f6e6b91d0a6af32914fbfd860087ef4d14ca4553cea4781cb9b075e47a9fac71c38779892c87a21ebd942a596be33fa3f8473e869d99213782866fe8ad4a79d4d2dcee9abdd53de125a179af9bda9a8b8fa9092ea6ef17b6260da9099ffb1cda671fcc364ad5e40bb4028115be8833c9c6ee381e64c20d1ef056cb5132a04dbebadf2e62f8c545808f685f8f08e817558f27ac120970d6fb1250ae469d33f181ce62aa6a150fec671bc669427151da2e8de1f010c572a000172ca2a140ffd253a48c612c413eac55e9087817b42a468e929e116f4e33a63df26934e2478e806a583493c985f75c4edac0280317bfdb572f1ae1452aa26f3076e7e48fc91a253d689dfa76bb46b199abbfd6c5533da987747dbe90a4c9a8ca664661d8f09df9a2b6648e2b7185f459084f35a3d56f773da2bfc70b1d7ab0ddea709362afb0435c6e6f6a58d0cc42da9a884d76123b6df031accef92a77b67a906abe90abd54ffd358bd9aa977f926a71bc46a5d9b13ee0e4b761771ca5538601cbc7204463f3bc3821e06738acd83cbaf7571abbf032e9607ab7be96baee4ba563932f172ddee5d6adfa4c01b21439e8fa80101847ae4cf5ba289d46fd65545a45fb7f4186e02cf9a0aa2841bacd3c463d6f23ac88514c9039987671fdb263621b4ce663c7838dea4568905a5f1fa3ee4d82f222579ce278e145785c5403bcb37825d3f787ed3f4a657c7d06a77c31afdd33f4042d6baffa3898da308a9a2f367203bf5e6afa82a6d5c428cd8b8bfbf98a505cdd24282867d89d7dcc7ff7f56cfbfe6ed07ebb3fa36ce68ff1cbd2141a656a7e62ddd90e5fe72308c5a2a3a5f198bed49e4b7d373ae4920ea0ba52b3c9d8bd9fa45a655bbad9ebfc64f06a759a79d97f0693f73d25700a7aa7dad283b88c9d62d07951642561911f11e1c7bd760c9a021cbab298b0bddbccf828a2d203a10e36b7dc7d5f40df67c226a9a423f8e42a62a3e91b3ce9524e0bf9d2d18e07e1d0fcfb8c67693168871de6b5e683c0dcf46e95ce63b5887d2538f76078121a5cf124f2f0c06226387fe22be207b8b966b59f12a702bfbd6b00ba9b6d9ce2beec702e262af32ecdbf54811850c51ce03544087d7b0a292a87e0ae406e772bcfb02c84c513e05836ce62116a2e21920bd219d49d0d888156577204b6222e1b017a9bf5f6d57f43011ec2631a6323ee0238e89d0cb2b20b504c485f8a2a001e79d3ef7f56b71e8fd30add6013dddd984a2b5ceed885afd9b59bc639fb2dbc5903acb55bb2612e4bb7606f5431d864a12770f0cda1ab87a9323a40a8db68214aad3a00e3fcbf12d2327e33c658f629edb36355de41e91bc9ab3f4ae43dc43c7f457a28f51eb1e27a34db532a4a869242848dc23399572f4a02d07a52c58e8829d1c1a6e2cd123707240e1abf62f737ece64cfca027b31ff67d9dd567d4ca309f18a91d27a40fd2a4c1bb9297ac329222675d533d048d27909acd0d562589c137d6c0b4534ed1488eebc2e823eaecc1de95f120d2fa5292257c6c0e00b4352fe3da2880d08b7e4594770d2d0c8c5f2ffbc349b7555739226e5fc3c1f1e4effe5072f1fd8a6eb1bedfa334dfd7c6bed3580f5209773d7c1c133d26b758b7132436810f27f497b7470ea735fec626eb95b9d301ce012c8f61aa4db918c38baf9d52c67c0b2add59693bfed42a4e0263a7edcf473a481ee870260f3e8b22a42a820be4b65e797b801a86e2693a3d9364f687aff0a7177a6a3d35c535239585688255a2e378de152b88133be4a0524ad6ab72b539006e21f67cbe460ac56fb696174b87cff050b2c577b59c0c4b1677e5e325ea0b7d89d68a2438d9a2dcdfd898b05327bc8a8fb9c7df586c7659ed64de3032bce462832304726aa0f842cc12a4872172bbb364b5cb7e5d24eeb2d332d15bfafa591c9616363d945f14ff46c6b98ccbdc8e949a5647312fee2b8fdcf3ecbff2d7e259ef14d5beaa0cafdc81d8434afa394ca66769d230811330f7b1f68b6be89ac987a45904fc4e853134d5d3a6a140fb56a5e8decc3c37d98cfe3a9b43928f2e01efe9518a6bb7749dca1d7ae8089ee2e3861151c260c5a484e2f563c518bdffe45b2488cdd8e9e965aeab01bf894192b5987f1e96e18f75266e21e72c5a728ed2995a1605b33e8ecb21a9d56d25938730d6936c701a49a155eecb39075e4da05849c67dae2f2ad40962837ccd03743cc331e1b09dbba32ccffd77895201999664638a2b035fb346d2a65b3236253874cf6fd250666f68fa517328abf9014dc8545736eefbe2649140510f9e669b2e28bed80f2618898bd2eeffa0fb5e7f962f685d42a7f694255a33335842dd5f7f48969252a35edf0f8e6920ae85fd2836f89d358c3e451ef5c843c071230a2fe30ec1efac1e58fb506267a50043fe6b9b0aedaae9208520d7285bffa2857d0c7d276e9b7523a1c22b8889c5295b5a539387d6738b996964071e25841edee21f1884ef73fe4c1fafa393dbeb0a6bcb56598762c554ac650797c90fccf5973fca168c3a9ccf0570a791c80be4840039083318589138f566ed5a0222e4af8ff3a3569e4dd5914644208b2289e790f15e5b4c3daf9d4033b4e1c77c878fee8493e5b0f6f4a4ff5657922c0642a7fef854e5a1620af30d8804abc4315cffb8e271991353556fd2e957c235e028c2afbf0a2c35a998cfe3c87f1e9bf0da9bfa73a67e5a6f3ab73c9ffd554c82fe52b742a25587d43fe6675915f2e509a7f0c6566196f4c5aae24bd495579026328a85f668f685466fdf7f76a8becd25b2cbbac3efb8306b2691451414407ee41fa1471055a2ab02f5ec99b2c612d0d1cd16f1af866e773d6aec53ed2dda0fb6bb140b766c0b3a0f8e6012b7d67554e7c7a1876f51d0cffbee1fc1a11d46257bfca462c7a9c17a4f872476b9aebe991846fcd10c431beba46f02cb0376a632c4b6e8b10cae1eff3d96224886c1d885a8c46d9dc80e6a5edcde5d436b902cb0565be77baad995411199151f5ea61ac1d7ca5014fc2ebc01a8cb9d1e7662dd93f253eee23f474bf3a25285c4e992a0f77e7c707a412d50e5a04f49f1069a9b810f2ddc9ec9f468c389279b75bddc6beaeaacee970c768a05e1ca667a796cc4a5acf756401959738079b0578a61a80c1329ab59bdd2bc62fa98178b3acb2972d47539d7b97bdae13a81be76eac592537d096902a248eddcc8200030df3f9a2963ae7c8a3a86e83595940810a619b063d9bc6fc0cb75035e988acac64480f5a1a31a787855d8a83013919a793d4de679a6810208aae6835ba9aae843e6cde97ec57296398ec3c128891f3c7e44f3fe0c9779350f66f55ec3be94f9eed53dc6ebfbe53ed427cc44089a70100e605f554f9410bbbf77adbad858ce214f06ab334228b8f894fb7a9b2e3b4b53baa67fd4311fb910c424cdc486e6739cd432a711f570699a903c52a7071c2948a5c6c9d125abadccd242e24c2871e83d7c048dd2da6a476466a9ec31a35a652c06be1eaea5b6820e87f880d9b2faf5c2a7e60355e4a941e1b748fba735d0e75dfec06c6a9f2e57f12171ec9d6c69c0fbe3c6808324175ab324efaba125a22cecb55d7be793e6799d6a8c2a64774ecf894b09ee626146d46ee5b6875e74459751e16b62a4feabc675d887910cea345bdd470fca4229237d4ff79b7673a974bac5da0cd2f3df6ecd0c21ea039acb0cfc74472a7a97a2116d3250f183d0e427228a9602fe6d39497b02713c61e478b5c1dc68aa0d1e0294d7a5bd9bf4b8182d2cbaa1b9455c2cd2ee1120c83166d6f2dddf1311f40168fbad45b1c7afab59b95077540e64b638c159dda711a35e0bcfbcdc89f8ee8da56d7dfa2e23f39e8dfca2033783a3380c031deef512177f7128400ca8f49d8cdcac9ee38a5f86b8ff90664418509fee67e383bfbb478d7434ff7a6f50f6b4a279be9ab33b7270658f129e4f56526f32b38887eeeb13e2b068bca0914e730397ce5003d181f777b45744bc43fd05141178878e2f2705017b4616d23ea244d54aadc74c4d8ef3cbca173964a50521b13cf235c4348930f1c7d17552bf9f89c988f977ed6078fbda9f23d81e117404fac83961b7d23a91c7de2a5aeaeedc8ebaee2f0f76d9327e81a1f23fddc05cc577e4c0dbfed207bea589963c00c96ad79f2360d470e3304ad86d203e1c24738973b46bf04609f1f744dd1975c0c7f7f4e7a337bffbe7c9e83fba1c69c6e18287f3afa2d3996ffc1bd5193ce2b52444fdcdb0b19f701297d88d0fa29962cec5d2ef399feafe95db1f5e8c3c645ae63750de0406d519710dbeaaeef4139aa1b9687f4cf3ff77cf42acc00833bded8e853cfe5ffb8a369800b227fdeaaf6f54c182aa21d1398b29016cc7d468424beef0f5babde8ec7b1b7259b0fa178d98a5e2e2a6f100fc9b2dcc4ee5ea49b240bac283c9e4657eaee6a3f266b7f091d30e96666c14f1285a8671d02656a3e5583d4a4850da032e27bc13845a807b36a974593b1d232bc7742f3f20d1111781746deb4ea6ac95653a1acdf4f649bc060044d3224147133b44bd88fb13caebc41b36f7e48ec97b21e405ec941b270960837be1d49179664567d1ee2342cef5f9e4a559c7b27aa5aeb094a60845308aaa9c2afe5fd4cb808a44e4b6211111a69b40862e530247320863b7fd37fa77e69f05e05a8c43b51d3dbbaf3c715e5c348abfcfc5673f8c21a8126c762325ae3cffae51ffd43cee880f480006b7ef63e3a9ac33e6389466ef1a0b0e67e47537db6bf0f4950f735df6cd81ac960084df5f17d827ab400c074f8fc09bc5353bdd8cd17c6dec09842e7fdfe283f7f33133b33b704da89184ac05b9f98f0b64a5a437647107438cbacb161b6ec97814f56928e800ae519efd7129bfbcbcd4b305a9c703ec4c2b7fc685030e741f951e182da0e0297f99b28a1adec735e4a8b571e79035b78513b6ec12d815323fda7ed61353c52d490186450359c7fda3b45258bf276ee655cebb8bb23b20067bb914cfa50510832e93be450dfb9b7938d3e9888632938ba8d52760169055359373a558a7e2db3e3f7d31476c638a263c48b02f73131c737be93f29b9d9612b6d91434a26e6bce2b536a16d866985ad835a995781cb72680b8a5ab806da807bc77b9ab0f5cc39e845e2be7599db544dccf61c214b998469e8e7e568db4d171b66eddcecfcbc74535753a1b430c91c64e4ef97fbb70bc2468173d0362940a1379d90b358806eb49c2632398b2572b3d821cb12c0fc32c68106d6357b26ea2cce6c6fa8e1a17bda0fa64820c450752483cd066900f36ecbfc34b100799756296d7e46e48c5c48d38cdf333b98a8c7aa1adc2b02b58a0189f2cd046a18d1778192d98cd9510b40fb35350361fc4c3e917ac19c372f196e52c976c083ed500b4238f636fe21b9f3c362bd2556b16e45f67de52aa2e8f08d92bc19fd18a0030591df154df34ef121eac4ab0cba5b5fe8920c4c3f3a63a20f439ea9dcda4ec0d7601fe8849aff4f5d4d5552cab4c73b34d41543551fe1008032d101fe1d94ab4943256471f4bd06eff1f9593afab9fa8cd534d88258936cc593785464f4546b268f6adfd878911497d035a60a0e6c68b5884d76bb4898ad59c41160321b83d40a364cb427699c201ad78852a22eaaef3d5ceaf9de365018b271e16abf0ff5819345ed4764b70b88decf41c15dd243d81cc599a2fef2a3befb2949f2ab244fbcd412432ad3600eb5d92d116ba618f8730a477debcb3280d8b1dc04bed8b360ec7bb47b9cae89d25e702db37c5b583fd72c3f0c08a1495f75f15982a9931fca16b5b1ef1868c50a855116e6e0f49495ef82705f3a3c8d834d1725f0f0506060c2cc37e148f78f020fc701424fe46a5159e3a73dc834433d244568bbae114f475e5e60c13f47e9e14db1d21d451d2c5f39c39af0b60651d059a899af0181ba0b4c7fd5a7e1416adfb9f5381b24ce947b7d09a27a264acf7f0fa28d9db6f6f277d86e94ed96a4a53cbd3a7fe099d7177c2d6ec783314e08947f6811d60f069a1e65663b93f9aba00dd7de119c550181262340a88b316c191cff1c7b43d936a466c0226a5968c2e84ca61faf9a32cb3170fb8d105d25b3952395426d28531797154875af2cd089f7505dfa742c83a9fd15ea57427767df5db894e58f7e026eb4d126067eca69c7c2440d9e12486c63957013961c24359f94f5c1dc239bf532998ca339b3f0053961fa7b71c3c2a614d4b8a821b5e1a5544c4d079e71a43a7965c34e981a1c5460b25b6831979883e48f76c7ed34c844406cf5268936c01c3faf13a235b72444b9d7a701fa9a495231fcd8b8ed89ff2993e7a0241f8ff77e71badc7f0c471024a240f4824da0ace63db199ded2e6f3953c43cec3f5d60394f546eeac40331aa3f466af470311bff164fc90b00995228cda7e239b354a10269904304436ffc6f42c17e9b9ffe9a946c205fc0add8103e12e342b4542062ca0083c286a0be8ad469885fa7171c5526e2baa153c8cb43d33e9b1db7c635827ecd26041aa632829acbe53c38f63462e4d7a308f299efd555294be0894ecebd3a11d4242e1aef59cf77768197b77282aa0dd81d9085f87daf6bba680e40aa252629e2668d87eaf38be0e5399c95eccf3af5ef5b6b9d9da27251b8375343aba5406c6ae8f78d2311828bac89fad2291433cd2ee74ffb81fee1a3170ed32305ee77b1ecd22c7dc6b7b5b400d42917275058a2be78bcd1d79a661aee6ade1ce17fb1cbdbafbe2dffd3884dd87e14e36fd4a27a5c64d4f970541a75af417dadc969e6bb5f29415070e1078071472b5e043361e5747809bcb83af5cc5bb17b03ec564ed1349b563563233760c4553b0ce46a6adde8b4f1cbcf0cc33ccf6d8ec8551144992a0f530b012ec11e28de9a3564096637e590d549b8264c3aa1284270a9310496fea8d53024853bf30801c657fc2439f0446b3de62e556754805a5618eb99e3ff6acc52c898900a565139dc593c4b2a37fa9e212b646d9f4c7fbb204c2401ea0d838a806dc26c067a390f202bd3446cfda0a569c1cbd99be00c125ff13e330bf7b67f8e489c2191d73a74d3cdebf0bbc20ceb4c024bed7069d261cf7418fd07d305b03dec683dea3e3ad4f1ef8df8073f720be0761ba4c6473ae3e8344f76e7e7530258aae63b0b183b0d364ff7b53d35bb0182f8cb56bd550a5148737a1e7520cdfa5b11f0caa70390ad04d0e98664d47af518d6972fd4f803e5b395a68a3e08df1ae70e0aec356075f616c8a60502d45fdd6444ac5ed5d37d2f6083caf91fc5d9851e636ceb095169d44bb865387a60ff46a277ab2f9f6d8160f09d051bb581c3daafd79cc8d2d307335a7505573d2ef74d0f66ab4a432488c215b6b72faa1b672c5805f0e3265583947fea3f20e6b1f10b4dd717c0ce3088fafebc16d48ad74ee4cf5e059164700d3f50df68f2fb8d8b932918ec820c0de00eda4caf332a1139924cb9549c265339495fa248164c422fd6a31337a78320c8c31193101a9ef7202fe0ce9d30521ac08f0f71b3fe100625ff22cf651ee9494101ffa3b4e8c8c360bf03ce35a6c00e3a0a7f024f9757b4914cead8b17a52669fc31bb92efae1513aaa3c109916ea7c025298036cbc91c69b7a53d5774c1c28c9356e33caf4a5d6e9809bc11de2b3bb3f0d2573f8c28c8320b8a397ee9e384dbcad1d8a99d70cadc1c337d6c9c2207fed9f62963c46c866c79fdd4abaee40b62ab54b942dc2da4cd87dc404b742eaec64ccd087d2b60e06b1396765390f6f8c254bba3b0d5bc015100a67319fd198fb2850586b63d2d2b728d47aef097893178195064925954678bf2d7e5e31bc10ab8a315a0289c8152e7ce3051df782d81b7c49e4f171f1de5255b87d4801b0842318f60dda27545eb0c8797f77eec5a064d166da02f04faf7d809219fdb082abb41e0a59eb0c8eb4e7f2a260aebe453c59fb18794fe1bf21eb9eb330740081873e0d674f026d261f82b8262c2979a6c8b17a7cedc89a737f7a5a43e68f513a9c0cb084fb4723d230864186c8e465db6eff89efabc81c7b511453503847d69efcd625afee62118c8172fac335c0218adaa22e0b6b7a205e1cb0ec4dd27c769fd626eda9952cc2887c3e4e7c2586977e7145bd175ca45ad507a6ddfeffda0555ebe142cffc93ff70623f8fde34f24c6f9d654671bd784bb31fd0dc11da9bfe4577408527ec385d71ea1d3b739101083594e4e63f4156eb6c37541555344073f25e39cdc7a39c5a659f560c9ceab686cfea58fb62a1fa4c7aa3a35d91d4ff284706054615d0782bbb6dfb3b07a5fc80df69f1292556f2ff044d1728be0a4604118386c199a19d467bcf118b5b07b4a52181c73d6bda19f8952683c56b61fcf096067f00e47cd106626aa6e3806a80ceeb33acdd8ae7390252c815629473d79abfa9368e0c6c546624a60b011715b87fb8d5cc9a1f028f1079ade65b35291bb0b1fa5f02b6072a40a78275e2ec4784e41d16fd83357ab084935f6d7896788ce7cba108896c0e865b303fed152a8ec3c664f4b135739a671d3a8335b1960a1727d451c85f0e5562fa021088eb45a7f694371d16c21f7b136b9642e817cad5135901de9122756bb776eac02b894d04e198ae881e0af62b79dab09db20311c83e69852ee7b5c13a546714dbceb221b0440af333c3c4344f4fc324c301a60d1f183e7330f110ed3596e253fa8c693063f5f9599faa778b1afbe68eb2f832af2a6acb250d7236e956d0fd56eded2ee11caa420a2687fdf82a74785366aa22e916d75ad1597ea3d2f9a0c5b6d07a4d557a931022bbdd36b4bbc75e97c3fda081facc8cc0782f902771166d34c8ea91147d1c7b7ec857881fdd5425581f1d027ffd2108ee15a9b81196b29059a5791850f6f330b47bc5c7180db701fa81da7030cfda8e60f12a69172bac1651b7392a0927b93b28b42b5d2e9d590e736bfad55993d97cb1b79a1f519591e2c528bfbd0e5504189719b9cf4f7b0d155734cd43800daf07357d653f73370a02618bae488201846aacb31565b5b23e7aa818e70b5ece5dfe1cbeb945e449f3d425065925505e62a8bd5ea20f21667ba834d8cc52026857cf176677a658c7db9e27b0e0e0c479031960b9b3f6d06026e2d87c60c7135bfd63b9dcb2c00e46e5f042393ba7ff958ee8fa72c2c9e9594bb2fa9162c38688dd77c3ff7695303ce3fc79953453e2e2c7fe02628e53c52036297c0c2ac5f4630919bd359bb69225eca419c6a6c89c071d6716c6ec0093fc65712c2e7dd0be6ef7c7417aaecc60f83088b64bc0f247d038e921cf6fd1e47a59da17d62ed646fcc502aceed35870eebcf10881cf0ff712c302bb4e7eeca684b49fc90de7e12bd211ce2e0421d698c59ac3984d71d9b02164fe9cbe95966c4da5f8c4800fdccb6bc09e4056af229619ab9ab723ef6592c6bbf83fcc20dabf9f49511c4311a1a97cacfc030604334583e6f5ab08654ab43d9392722f40a41dfbd6035a5edc25fbe72ec02ac6775795a1fefa99c18948f548be1a636ebd24b697b0a59c00071b73a90511911d27c0b00926a79902d859a40d7f0a77488dcf5af259e818d05d186b0474a4425ec3abeadbe310922acf1ec22a615874764511bf80d16bbedfcf837323283c84971f9bcdcac612942fd12dbd1beb8f6b658da42f50863366552738016491073e24ec7ed6f429706ae4b90816471af4031be4e492c8c2a08ff1680e3d3d934f2e0a3e42cdf7214e3ef59af7b39842988a1f4cad45ad0ad419d0382f766560b861959132e76806ed08d5322da000d39845feaf455bc306af95a7684eea71b4ac31a972220ea22f029977030314b9a4b21f8c402b0bf2f41da5bd721179d7672ae77f48f9f682ffdf5bab3588cf8a49d31c002b7adb4434cfc5a05488ef8f26ac80dc153fabd6cebe61a04c2428aa04e037c977441b1bb93ed431c914ade76b0c08cc887e3d590f1e2a50308fa3c54b22d92f9b8ac39d485cb84eb6ffa0a51718693f58aad932695e169b7e41a4f4ce021362241472d13e2ef0c569110fa5f0d05f244e3e6f9b8a706817fa592b2f9117e8c2defa18ebfd1563cbe348c4f8de0a16e7acd71735a657f75ff196605d4ea3fbb120e954701c8c59e0bfeeee38f7312307ebcee061b4226d3eda9aad6eb31d460a0d3552e156f3e86489dff4a03791be54a6925ee5b07d0545896106bc847bdd561146ef646aa91b879f0de706c740bfdb5d1c3a732b640731436a62c431187e775b4880a0b2275a312a894779212407be25031e403d9f36cbfe07418dff4dd9fa6379d110416697ee0c114d113c6f99e04cc37286c3d6851c5ccf781250e5d3049d93d1917723751d8672639f0bb854f87564af445ac5cb47a1fd35864b6ae446eb1e4806a6f3bc9e4ca4bd191cf9d4b56530735b16254b920afa2415329f673bf921e849f0aa7b8c51f0e5b40756d04c19a1eff8b622965ecacf183bb07b2b4572630f97f6eadda879bc0fffbbc4bff7ed1e5aca9a847de2129a3c935c278af6c29eebcf58a1e6cf093aa44aca35c1bafa6e2a361218b000ff4a2a49c65e64c12344d94c5040d1e737f8bd78bf015ecbfea6ce19574837c5471dd660e673dbd703eae068521ac27f570786a952e37d4ef425607ad60fe45b09a228f18ee664d04652ee2cbb488d42a0c9faaf50f867afa41f1b68aa9d7967f15adda81deb18c00f29ea8a5e0775381cf931f58caacb54a7ac41db043747a218927fbebff95aa1520e136f366088a0c006a2fe6b61070626e0c083ede8c423acfdd70d0de04927a5d2f481d4cbd2485c5bc7aa22f6fe226be46be4a9dfa6d10253675bf0760f3131a11e169dcc62f4338fdc35ce0280f23483c2ccd2ed854b3666f6e8c02ca15be940edcb11e996a84a61db5b0f68fc6703a0aed9866396e26895aae65bde6d50f573ba0a6e45a6671bea93700223b866360ec5baeef69294666acacd89acf029fd7e66b37d0d1fdd9aa0a69a827c6506edd8e48a771cbd698b868de3d4d4440348f97a0ab76709d57139a1da8f1b9543252bb8778eb2f5be0ed17756e4ae806e341741dc992dd2f06608eadeb4cd819ac791f0d30901e622bafee36b5409c091193e4c0f5a5db5c516cfd9e40496cf91773e6d87817f639f8d47385df3a43a2bef3705c25f636414f9c2887a782bd786b7b1cde6793907b15eed4e9486c991f21e3a02f7d48dd9366ff8760d95a46751cf1d32c2e72515f36e0d98ad9a5f81a70c06d5c4560868c6d1990def3b94475b76664381f722fdabe739066c58370aa03a28aa5bd00432177b74d70f4cb53ab7f3a5459e99e1b430d1dd547c273214dbed7c3cdc673a0f5b924a860cce78aa1e8cca714b5f28471368e2fb5f41d2e72e6967e20adbcd5006dd31f644b4439ecfd62541f69d5c9810ca00df676a284d4646923f76dd4846d7f289d29cf3dd9770cc4fc2a2fda158264538584aabd66d28f71018252892b545992ddcdf4a40fa2f3a909abfe0da2e722178d70e83ccd21477581af360c93d33531b095951804c15f2dbb80d48a9db7ea9900edef9651f758c97683eaee8e61c0c88d30c4969920aa732c57f8c5a1aa2834b9f9c3285267dc4e56a381633d466a64b2085abfa052b13d812a6873efe6f2544650186fea789d6924599bc06046f151931d7b6b614b836a1246b8ae7ce4614563ecb68cf9a57cd3731f89e1a73951a2ace26289a366529a987592d18d4d326fd0a9f289a6a9517d4e33de1736ea2f9c5e2c52493378bfd5b4fb643eb17fa154728e29ddc1b2d6fea380205692aac60d3916ec163777a6fbf2fb8cdf840e09f910e29c85727812a62dc3a3a39afdc2ea167a5449e12c2ce1371a32d57ce5802cda1f28254f0d9c544080622df00e2c094011ea97e34edd702de6a84c1b156da47667699b63ada7d58c202fbc2f540c8d4fbf8cdc95f9b102257fac1f2f8ce5bfd2f50e99f7282d2463208c08b106782a1ebd4a135ae1afcb54319972689303d6a524307e29114a50cdb2f8c94fb0f204f637a16fea8261ae51ac33b3b1ab498213636b9c7f855b9a46308ffa1f8b6c8b25a2b6065920f9a20833f9c097b8f48dae00ff898d7d462e55dab5aa07f9d1396504b8e42eecec392fca1f64c30305e02602f5b454c4a562bb17aab60970d440d913b8db0aae3383e1f3f013d7019e3e9d69147810546b1dc6fd68c9f47ac3c4a67972b854055f4706ae4861e584aa855d42e4b5dfd61fd9d6673beb5801d2e31bd7dd78091d474d7ade651dbe5ea208360be3ef1aeebd9e38681768c0783193d1c4474f913a2b4c395ed725ba539a6d6a0ad31015248c84805bf0cd35449653e8801a6a397f228d385e8cc8da401fbc8c111de9dde1257c0cae82220202870abc1a1112b807287b06d08f9d33ff02e81a19fd66f02ce48b71524b5a5177f80b3674105d56234bf717bf682f63943f9a6464638053561b78db54aeb6525035b39a01e610249af2c0b5f2b3b799f14f8c0ee76b66f09ac685ed9ba4678268441d14a22a4a65fd3d7d72816af4d842bdcef9bd20ecbbb42c6b6fd6668bcb0cc8c99fe5a30ae7ee5c850bec2d6296f91c2c1976fa55a4c9cbdaaebdc8f718475951affbe88c3af773953001c08ae069e1cf40bb9799f569954b33c3f4330c74652f088ab669c8b7cd93c5557be761764be9e85b0f07439d28b8e9977586922dfe4c287bdc4122fbe6378923c86bc586fb547b1012f92b2a75047f7a48f88e1730408bf53a6b6ea2c905d1807916be1e0288294cc466ee73f909ead23f31ef36b61e5df581f382c81aabc761f45547288621d16ba21e52c14b92c93e276c22f2b4ce5106928cdd0cdeb67dcdf8ef98db1a701e9f196a2cf3353a27bdcfd5ea32f8cb53795c40beaec2e33bb3ceeb980688709a6f875a2ea891367aa7b1d5b5de2f90d717d2efea3a3ab71777d1f4c7d758487f2114f5ad4062b31b08fefd3edda89982138e4185ed9f4cdd122761389e06bd4eabf217d4197b3fa1a0691a96f7b1ea33624e528132c104b25f0440236ee38df45c1581a68d1fb44e1bf29c3a191cc95ecc2fe09c38c78bba281cf51d51f06a22ea1cd6476b077c6deca2c278606fe8d6efd65dcf9fcbb7e984d75e69ee6e1989427c510034fd4501f75ffbaaf813bbbeb148dd1019d45e2e6ad33a22304f9cbcc54b78c8c3ce958f8a75a2a777f092dbe3b88344f84d93dc9bbec0aa9287a9859c740dd4dd7bf28e5222cabd4a525260a94996ab21d70c4c82ae42d7c802dc9e7377be23b15e5c13872b0a49ce3894c60bd1aa235fcff8d4af6fb85656376a5fd0409fc4b33419f9a4f70462baa3534bb8ed68b8ca471adf0e11d5ba51d4b614b678231e3036fbd5c632d956298ea9fe845727486896056d0c03ccdd1c9e8a9a60473db4e6face0c4edd3d0353fc588e24e6b428050f18974d8c85c7cbe95dab305b6720dc14c21b1550743e335263c756399ff8091f48da7cdfd9e1fe4790cb337e8db7640f2916fb910bce94e76c9dba93ce0c72c297c340c76da7895a75729b2e103646d91170978de2abb1544927d473113947c2fc1e048cc08bde0fe3e5e0afb144fde4fb7328545b05b100e432ed26d16e435fe4d6c0a4413a8041614569ccaf741e8d3e4eac01490c890fa924792a080750f582a538afcb5851be494f8bfb0649287fd01b5fe10f7402ec63899c67ba5c2d377683425d4b079b62e13e6debe7d6cfaf1f7e8f6def16902a725e89840eeef41fb54d74e97777a31e5275cbe2c6b49428cc11c34a334f967c3be7c8228b77029e494a7f30f0f774f9d7b3ac9cbb0792e5af1b1cc7bf8250b879a558fe1dcf0e47f9eed867580bed13bf0880693a1eac8eefa43ad554f64f8c07aebb280f71112a168c320b4a2cb757c2f0aba3f7168c4dc1ad9a95a959ebee8c4057eb6a67df2d80a815291ab340fe4e1c7edc4ea32ef97eddc3a1806d4da1edc07ab7362a215be04c47d9d204f644ac4463a9aca3b6620cae9842a2c4140c724fd7f73ea8a7adb19143907af6e3850a5851334062cace2722124fa72935979ddda0aaf71b3d0cb11b3ef12e955e87ce03bef2f686354b8023b45933787146beb2844f6bbb3e4e6278270b700e73b3b2c4513a9e8de1fbc15ca0f7b76f5386acddeb400452b6fe7e60d109ddf62a3404b1b3738de303d0e824796e1737c35e1077af37d5f8d915c8ab71a16635c60e18d76b3c9280d876a34fb0973b87ffc3d4761075e1f30a2be34621baf1c73cdffc7f965e590a63ad34897c27047df2140c976b62c7cc9f02fcefd07d9c0ce7ddeee9cc6dd7b20245a7a08268e2246044e84474969e1eb63930f495750917bc0975a0c65feb4d5a1d87a2ea7e1508cb2436f319adccc4618bf5bc1885d0e1fd3f254d5779037ecca9649879f1236cfd843bc832c2a7c2d79e6775fffa67da8bb582e400b36a5b95a7efd3bc6d33dacc0e2588c713fdb46c87095b629294efa9f197784766cbc697b84c874ff109705f2c0b6c2570b3d90f5b85d84a5e1ab2a037136d187e37a7cb33b406b3011fa3897e649ee63ab76022db7dd2d0eb1b7ae97088b19634ff9970bc1cedd6d20f5c67772e8096c634a7dade70f5f92710e41ee9d8dc3515d7d1d73a8a6190e1db33e2066bd26a9e828a1b8f90f7ff12a2f23627f75fea4164c19ec1ac04b942e6f2013bfe2c2e43c2b57f3b21024429b468c6d1a1dff7540614abd4bc82d5d9b059bde8b1031f96cda606fe9e94136b4290bd046c5e2818ecda86bb7e1fef74caebae4d090b6a58e12edfe52362a681dc64e378ab008550c883fa84b062b778fe2db472f32ca3fb2f74df7be06ef0a85f2fa019260c5cc1e66d7fe6d6962bf8762e9149a689749f3b871e88e5a8d4a61490dc8c701dc8ca3e920067613e907f5c736d68c792672895b47e9e797d0253bec32b9d5a79e0a433e1601d5e5072b7660b5ebed7e67bc95a6223176625290382192efaff0436ff1c704e9f76e1c64d83fed9472197a6bc000bcc24d02e5400efee09bc5881aee9bc801826cde13fc6d22a0a9dbfe4cb171c9528a0240b8ded6f922c77de1360939fa0bbe4fb82c3105f22c90040958b1cfad71423aa7fc3624e0d22a4e9da57e3dc09950a599266fa71c0841f80764e96a096e1ce4ad161c0cb5348bb5248513b4740748d10b423b9cbc95cbe6ae43040a5eed2ae2cfc7eb34081595ab6b2dd1fd7480089ee2e8fbcd06c6dc43a3243c9c4450f05c28559df8c0fc41cadb644854825662d1475c00dcec00818b746a286dc12acc5175a04d0ab685b48c76b40bd0790afa606be65e6c7df5e027f8bbd6979f00a08cb985b68a64f1604e6386715a4aa242d8176e43f6d8147dd64377a4f44d24fa3ed06323746207d95bf6323b61b42f4903d32f6235a77f98c25ce6ebe8d5f8b76d689267ecffe9c32b7dde34c7f43da41ce215456f1423572b78b116af081226c54eb0fcd8272890ea4ff1ccf91614c309cace805da498eb7b538f2f5e08d99f46d1f57981c5d8488301fd00d11f484e13c00bab448bdace012d2951db621aea02e2a1efd5638931f55faaa0c62e9a3d25ee26ef6a57ff22836b331e9d4d9179d5297972891bcdfeb695e9d296e61798456f9c7ace85c8e767211c5b586eaa114c74dcbcaaf8acc932707f42c775032e1f771428bb60c6fbca0e34e17a20ff52f4616516c60ff59a0b81f9908faae30985bb3126f98fd57aefe7e5b62098f47f35be80891ce4f9c4c6991b817128e3917b91d6fddb764b19e9e705c9fc3b45d1bb4fd4e0e06aabb40ca9f276f618e98856fa6eefb1646070e7504247df6dace32b472aa7dc41e633f086ab7d4ff34874c544d07d5679e7a8ac5f36672cf59ccadcf0c002e9f9322ca34a1691690a06b2f6dc2dd5d1b705490c8bd3acadea5d4e7dde44bfde584a62bfc85ad067be0e3a733e27ce017cac0230bfa5c53bf423dbd2f02ef0b95678a215afdd0480d0f1d7a1c709398e3448eb7b7c77c33570dfe545a81c6984c1bf19584953641daa62be86c17ae3b0c39daa12e0ddc5c40998f64abea505af6ac562d79d5f33cc19954348b0ed03028e71f6ee00962b0a3cbfc3ed78e92b58da538e8d4f65699a96bc41987f1b13aeaeb6fabab6b9bc9bb9e30ebb96a7a5817b73061d368a356f3d332e77da5e0f16d5f4fd981c132ca92cf6f6ad0f6ddbbb8f20912c4cb8a806e3386f39b7c5f668763366d01a4d69b5b0516b1b8b0930e7211cc060ef0d0de91e49656ffa28cb3ba42f4c2a31892eb91effff5f607b3bbcbc61733e8eff2680547ba75f37d4a7a6fd49019dabd5844aa2077dc5783919beb2c0a1f2601eaacc0ef67d61a70a8c9c248de2af03294e86f555ec59ac8c86d78a35c450ee80d7bab2b72761412cb54250b27aa3dd40b23532ecb3a14fd7fb6d0ab584a3677f6b1a373a1400100439edb5e011c9595daaa69fbccbdd1621f8ea08f21d4ba9dec01f2b75b6579f5010bf6538de8240a266eefd7e2fc9f2096c23465b5d545627737f162f8c5691c0eb07fe59879d55fad9174ada4043b9ccca80e2c9919d005e339f71802c6e64107e5d939921989642da4e3a24ee3d58ef82e99a54a4d4b2c732d114a823d6edafede047b8877713abd0a37da3086c64abd0cfbb2914d41fbcb6c33daf9405e371dca44f9b085bd7ce80ce5dc10847111cb72a6fa0ddc4d4f5fa7284c4becc389936cddbd759338701adaddcdc68be01cff14f472d30aea3189ae4dce09afbdc6d41405e16dce2f667bfba5600d7cbdec3d4d30041544dd461fa876c085c15de206ea8a00b90f89b5b010622d246b63a11dd57780c09e6e66288141e5191c9aa4d3887989cf2960b5f7d7d0a00b4fafe80691e335e8836cafefb784c05c4c13542d47123df54b71503998f750520e6226690a6d0e933adad8555f519c8e08d4835ff8826d9e975ced67b2084b5f20c5e2e2de0f32bd0cb3bc760174c9e3d383a4d45af9505d2c1cd4ea892cb0190d0ec47f1269623937425aa3725366ac712f7e30358de56b757912fbab0e73dd0d5672f0e23ae501930c7cd82b10dcd41815ce7135b8013e8a5ef854dca11b7c984d9da15547820604df6d0e30b896da0ab8329306220a4d095c610566196961f840733f872dec575ae58c11cf507248d3a5a017bef3c939bd05b789a41fa6d0ee0e41b72e62aedefd033cceae2e13404eaf2f3ba109c6cdb10cfa8b4e6a78ac3ee7978a273c999bca8a58930f4914044ba6605638ef5dff33b6b4b1fc7cd76ce502060affcb5232760f8aecf01825c14e3d1c0332b98a01747965b8e62c1cba3a865754aeeffc1a3fe38683a0ae89f7320b1ba314f1bc5dc2b47b094ba9242e7473245e6feb8e5fa63699f320c755e4b81f8fdc22d277d62d50bf1ac0a33047b7ef43c9eaad8376e3049b7a772cd5a21fa3a1358efa46857699cdf4e26ca3541f8a508b9f4baead07e9b8522081461f3a965547dbb7a43cd53f804419bb9ecccd7e0be09f69b07d320d52db53be1be2f6b4dc4ff8b7665681e9ba4cc8b6ac989bac9002a15913d0600e7100cd086494fb0d44da52a13627adb6089d8634288b08e9843ce090e79c37a286d9facda1126adc9bcac24faf62650f793407c36bb71a4e26526c7c84521aef3a7c702773ec2e4d9648a2269d86002a11325dd8eebabd321a4f6478cb670b8fc5b1ec5346b58e57915a776dd1830854a81f2716b089a336d3c4c9bde6337c9ebb94f269d9990028c04fb12ca59c2eb490470e33534d8efb250b518d7e2b23d515a716905e8e5200343adb21ee504195f282c913534a76452a49c76b8f5c33a8a174f5052dc3db943565e6fccbc36e7951a1063c8410a454b7fad8e54a021340062d2fdf94981dd6d88995014a11a7dbe244b401ff88d6f780ae1c0945d4fd88c2c3426296bc2c80");
        assertTrue(Hex.toHexString(s), Arrays.areEqual(expected, s));

        sig = Signature.getInstance("SLH-DSA", "BC");

        sig.initVerify(kp.getPublic());

        sig.update(msg, 0, msg.length);

        assertTrue(sig.verify(s));
    }
      */
    public void testSphincsRandomSigSHAKE()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("SLH-DSA", "BC");

        kpg.initialize(SLHDSAParameterSpec.slh_dsa_shake_256f, new SecureRandom());

        KeyPair kp = kpg.generateKeyPair();

        Signature sig = Signature.getInstance("SLH-DSA", "BC");

        sig.initSign(kp.getPrivate(), new SecureRandom());

        sig.update(msg, 0, msg.length);

        byte[] s = sig.sign();

        sig = Signature.getInstance("SLH-DSA", "BC");

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

