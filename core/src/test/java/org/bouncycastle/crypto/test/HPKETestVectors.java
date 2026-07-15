package org.bouncycastle.crypto.test;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.hpke.AEAD;
import org.bouncycastle.crypto.hpke.HPKE;
import org.bouncycastle.crypto.hpke.HPKEContext;
import org.bouncycastle.crypto.hpke.HPKEContextWithEncapsulation;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.math.ec.rfc7748.X25519;
import org.bouncycastle.math.ec.rfc7748.X448;
import org.bouncycastle.test.TestResourceFinder;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

import junit.framework.TestCase;

public class HPKETestVectors
        extends TestCase
{

    static class Export
    {
        byte[] exporterContext;
        int L;
        byte[] exportedValue;

        Export(byte[] exporterContext, int L, byte[] exportedValue)
        {
            this.exporterContext = exporterContext;
            this.L = L;
            this.exportedValue = exportedValue;
        }
    }

    static class Encryption
    {
        byte[] aad;
        byte[] ct;
        byte[] nonce;
        byte[] pt;

        Encryption(byte[] aad, byte[] ct, byte[] nonce, byte[] pt)
        {
            this.aad = aad;
            this.ct = ct;
            this.nonce = nonce;
            this.pt = pt;
        }

    }

    public void testBaseOneShotPairwise()
            throws Exception
    {
        // test base oneshot pairwise
        HPKE hpke = new HPKE((byte) 0, (short) 16, (short) 1, (short) 1);

        AsymmetricCipherKeyPair kp = hpke.generatePrivateKey();
        byte[][] output = hpke.seal(kp.getPublic(), "info".getBytes(), "aad".getBytes(), "message".getBytes(), null, null, null);
        byte[] ct = output[0];
        byte[] encap = output[1];

        byte[] message = hpke.open(encap, kp, "info".getBytes(), "aad".getBytes(), ct, null, null, null);
        assertTrue( "Failed", Arrays.areEqual(message, "message".getBytes()));

        try
        {
            byte[] brokenCt = Arrays.concatenate(ct, "eh".getBytes());
            hpke.open(encap, kp, "info".getBytes(), "aad".getBytes(), brokenCt, null, null, null);
            fail("no exception");
        }
        catch (InvalidCipherTextException e)
        {
            assertEquals("Failed", "mac check in GCM failed", e.getMessage());
        }
    }
    public void testAuthOneShotPairwise()
            throws Exception
    {
        // test base oneshot pairwise
        HPKE hpke = new HPKE((byte) 2, (short) 18, (short) 1, (short) 1);

        AsymmetricCipherKeyPair reciever = hpke.generatePrivateKey();
        AsymmetricCipherKeyPair sender = hpke.generatePrivateKey();

        byte[][] output = hpke.seal(reciever.getPublic(), "info".getBytes(), "aad".getBytes(), "message".getBytes(), null, null, sender);
        byte[] ct = output[0];
        byte[] encap = output[1];

        byte[] message = hpke.open(encap, reciever, "info".getBytes(), "aad".getBytes(), ct, null, null, sender.getPublic());
        assertTrue( "Failed", Arrays.areEqual(message, "message".getBytes()));

        // incorrect ct/tag
        try
        {
            byte[] brokenCt = Arrays.concatenate(ct, "eh".getBytes());
            hpke.open(encap, reciever, "info".getBytes(), "aad".getBytes(), brokenCt, null, null, sender.getPublic());
            fail("no exception");
        }
        catch (InvalidCipherTextException e)
        {
            assertEquals("Failed", "mac check in GCM failed", e.getMessage());
        }

        // incorrect public key
        try
        {
            message = hpke.open(encap, reciever, "info".getBytes(), "aad".getBytes(), ct, null, null, reciever.getPublic());
            fail("no exception");
        }
        catch (InvalidCipherTextException e)
        {
            assertEquals("Failed", "mac check in GCM failed", e.getMessage());
        }

    }

    public void testBasePairwise()
            throws Exception
    {
        HPKE hpke = new HPKE((byte) 0, (short) 16, (short) 1, (short) 1);

        AsymmetricCipherKeyPair receiver = hpke.generatePrivateKey();

        HPKEContextWithEncapsulation ctxS = hpke.setupBaseS(receiver.getPublic(), "info".getBytes());
        HPKEContext ctxR = hpke.setupBaseR(ctxS.getEncapsulation(), receiver, "info".getBytes());

        assertTrue(Arrays.areEqual(ctxS.export("context".getBytes(), 512), ctxR.export("context".getBytes(), 512)));

        byte[] aad = new byte[32];
        byte[] message = new byte[128];
        byte[] ct;
        SecureRandom random = new SecureRandom();
        for (int i = 0; i < 128; i++)
        {
            random.nextBytes(aad);
            random.nextBytes(message);
            ct = ctxS.seal(aad, message);
            assertTrue(Arrays.areEqual(message, ctxR.open(aad, ct)));
        }
    }

    public void testAuthPairwise()
            throws Exception
    {
        HPKE hpke = new HPKE((byte) 2, (short) 16, (short) 1, (short) 1);

        AsymmetricCipherKeyPair receiver = hpke.generatePrivateKey();
        AsymmetricCipherKeyPair sender = hpke.generatePrivateKey();

        HPKEContextWithEncapsulation ctxS = hpke.setupAuthS(receiver.getPublic(), "info".getBytes(), sender);
        HPKEContext ctxR = hpke.setupAuthR(ctxS.getEncapsulation(), receiver, "info".getBytes(), sender.getPublic());

        assertTrue(Arrays.areEqual(ctxS.export("context".getBytes(), 512), ctxR.export("context".getBytes(), 512)));

        byte[] aad = new byte[32];
        byte[] message = new byte[128];
        byte[] ct;
        SecureRandom random = new SecureRandom();
        for (int i = 0; i < 128; i++)
        {
            random.nextBytes(aad);
            random.nextBytes(message);
            ct = ctxS.seal(aad, message);
            assertTrue(Arrays.areEqual(message, ctxR.open(aad, ct)));
        }
    }



    //todo test for not implemented for export only aead


    // X-Wing test vector 1 from draft-connolly-cfrg-xwing-kem-07, Appendix C.
    private static final byte[] xwingSeed = Hex.decode("7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26");
    private static final byte[] xwingEseed = Hex.decode("3cb1eea988004b93103cfb0aeefd2a686e01fa4a58e8a3639ca8a1e3f9ae57e235b8cc873c23dc62b8d260169afa2f75ab916a58d974918835d25e6a435085b2");
    private static final byte[] xwingPub = Hex.decode(
        "e2236b35a8c24b39b10aa1323a96a919a2ced88400633a7b07131713fc14b2b5b19cfc3da5fa1a92c49f25513e0fd30d6b1611c9ab9635d7086727a4b7d21d34" +
        "244e66969cf15b3b2a785329f61b096b277ea037383479a6b556de7231fe4b7fa9c9ac24c0699a0018a5253401bacfa905ca816573e56a2d2e067e9b7287533b" +
        "a13a937dedb31fa44baced40769923610034ae31e619a170245199b3c5c39864859fe1b4c9717a07c30495bdfb98a0a002ccf56c1286cef5041dede3c44cf16b" +
        "f562c7448518026b3d8b9940680abd38a1575fd27b58da063bfac32c39c30869374c05c1aeb1898b6b303cc68be455346ee0af699636224a148ca2aea1046311" +
        "1c709f69b69c70ce8538746698c4c60a9aef0030c7924ceec42a5d36816f545eae13293460b3acb37ea0e13d70e4aa78686da398a8397c08eaf96882113fe4f7" +
        "bad4da40b0501e1c753efe73053c87014e8661c33099afe8bede414a5b1aa27d8392b3e131e9a70c1055878240cad0f40d5fe3cdf85236ead97e2a97448363b2" +
        "808caafd516cd25052c5c362543c2517e4acd0e60ec07163009b6425fc32277acee71c24bab53ed9f29e74c66a0a3564955998d76b96a9a8b50d1635a4d7a67e" +
        "b42df5644d330457293a8042f53cc7a69288f17ed55827e82b28e82665a86a14fbd96645eca8172c044f83bc0d8c0b4c8626985631ca87af829068f1358963cb" +
        "333664ca482763ba3b3bb208577f9ba6ac62c25f76592743b64be519317714cb4102cb7b2f9a25b2b4f0615de31decd9ca55026d6da0b65111b16fe52feed8a4" +
        "87e144462a6dba93728f500b6ffc49e515569ef25fed17aff520507368253525860f58be3be61c964604a6ac814e6935596402a520a4670b3d284318866593d1" +
        "5a4bb01c35e3e587ee0c67d2880d6f2407fb7a70712b838deb96c5d7bf2b44bcf6038ccbe33fbcf51a54a584fe90083c91c7a6d43d4fb15f48c60c2fd66e0a8a" +
        "ad4ad64e5c42bb8877c0ebec2b5e387c8a988fdc23beb9e16c8757781e0a1499c61e138c21f216c29d076979871caa6942bafc090544bee99b54b16cb9a9a364" +
        "d6246d9f42cce53c66b59c45c8f9ae9299a75d15180c3c952151a91b7a10772429dc4cbae6fcc622fa8018c63439f890630b9928db6bb7f9438ae4065ed34d73" +
        "d486f3f52f90f0807dc88dfdd8c728e954f1ac35c06c000ce41a0582580e3bb57b672972890ac5e7988e7850657116f1b57d0809aaedec0bede1ae148148311c" +
        "6f7e317346e5189fb8cd635b986f8c0bdd27641c584b778b3a911a80be1c9692ab8e1bbb12839573cce19df183b45835bbb55052f9fc66a1678ef2a36dea7841" +
        "1e6c8d60501b4e60592d13698a943b509185db912e2ea10be06171236b327c71716094c964a68b03377f513a05bcd99c1f346583bb052977a10a12adfc758034" +
        "e5617da4c1276585e5774e1f3b9978b09d0e9c44d3bc86151c43aad185712717340223ac381d21150a04294e97bb13bbda21b5a182b6da969e19a7fd072737fa" +
        "8e880a53c2428e3d049b7d2197405296ddb361912a7bcf4827ced611d0c7a7da104dde4322095339f64a61d5bb108ff0bf4d780cae509fb22c256914193ff734" +
        "9042581237d522828824ee3bdfd07fb03f1f942d2ea179fe722f06cc03de5b69859edb06eff389b27dce59844570216223593d4ba32d9abac8cd049040ef6534");
    private static final byte[] xwingCt = Hex.decode(
        "b83aa828d4d62b9a83ceffe1d3d3bb1ef31264643c070c5798927e41fb07914a273f8f96e7826cd5375a283d7da885304c5de0516a0f0654243dc5b97f8bfeb8" +
        "31f68251219aabdd723bc6512041acbaef8af44265524942b902e68ffd23221cda70b1b55d776a92d1143ea3a0c475f63ee6890157c7116dae3f62bf72f60acd" +
        "2bb8cc31ce2ba0de364f52b8ed38c79d719715963a5dd3842d8e8b43ab704e4759b5327bf027c63c8fa857c4908d5a8a7b88ac7f2be394d93c3706ddd4e698cc" +
        "6ce370101f4d0213254238b4a2e8821b6e414a1cf20f6c1244b699046f5a01caa0a1a55516300b40d2048c77cc73afba79afeea9d2c0118bdf2adb8870dc328c" +
        "5516cc45b1a2058141039e2c90a110a9e16b318dfb53bd49a126d6b73f215787517b8917cc01cabd107d06859854ee8b4f9861c226d3764c87339ab16c3667d2" +
        "f49384e55456dd40414b70a6af841585f4c90c68725d57704ee8ee7ce6e2f9be582dbee985e038ffc346ebfb4e22158b6c84374a9ab4a44e1f91de5aac5197f8" +
        "9bc5e5442f51f9a5937b102ba3beaebf6e1c58380a4a5fedce4a4e5026f88f528f59ffd2db41752b3a3d90efabe463899b7d40870c530c8841e8712b733668ed" +
        "033adbfafb2d49d37a44d4064e5863eb0af0a08d47b3cc888373bc05f7a33b841bc2587c57eb69554e8a3767b7506917b6b70498727f16eac1a36ec8d8cfaf75" +
        "1549f2277db277e8a55a9a5106b23a0206b4721fa9b3048552c5bd5b594d6e247f38c18c591aea7f56249c72ce7b117afcc3a8621582f9cf71787e183dee0936" +
        "7976e98409ad9217a497df888042384d7707a6b78f5f7fb8409e3b535175373461b776002d799cbad62860be70573ecbe13b246e0da7e93a52168e0fb6a9756b" +
        "895ef7f0147a0dc81bfa644b088a9228160c0f9acf1379a2941cd28c06ebc80e44e17aa2f8177010afd78a97ce0868d1629ebb294c5151812c583daeb8868522" +
        "0f4da9118112e07041fcc24d5564a99fdbde28869fe0722387d7a9a4d16e1cc8555917e09944aa5ebaaaec2cf62693afad42a3f518fce67d273cc6c9fb5472b3" +
        "80e8573ec7de06a3ba2fd5f931d725b493026cb0acbd3fe62d00e4c790d965d7a03a3c0b4222ba8c2a9a16e2ac658f572ae0e746eafc4feba023576f08942278" +
        "a041fb82a70a595d5bacbf297ce2029898a71e5c3b0d1c6228b485b1ade509b35fbca7eca97b2132e7cb6bc465375146b7dceac969308ac0c2ac89e7863eb894" +
        "3015b24314cafb9c7c0e85fe543d56658c213632599efabfc1ec49dd8c88547bb2cc40c9d38cbd3099b4547840560531d0188cd1e9c23a0ebee0a03d5577d66b" +
        "1d2bcb4baaf21cc7fef1e03806ca96299df0dfbc56e1b2b43e4fc20c37f834c4af62127e7dae86c3c25a2f696ac8b589dec71d595bfbe94b5ed4bc07d800b330" +
        "796fda89edb77be0294136139354eb8cd37591578f9c600dd9be8ec6219fdd507adf3397ed4d68707b8d13b24ce4cd8fb22851bfe9d632407f31ed6f7cb1600d" +
        "e56f17576740ce2a32fc5145030145cfb97e63e0e41d354274a079d3e6fb2e15");

    private static final short[] PQ_KEM_IDS = { HPKE.kem_ML_KEM_512, HPKE.kem_ML_KEM_768, HPKE.kem_ML_KEM_1024, HPKE.kem_X_WING };

    public void testPQKemBaseOneShotPairwise()
        throws Exception
    {
        for (int i = 0; i != PQ_KEM_IDS.length; i++)
        {
            HPKE hpke = new HPKE(HPKE.mode_base, PQ_KEM_IDS[i], HPKE.kdf_HKDF_SHA256, HPKE.aead_AES_GCM128);

            AsymmetricCipherKeyPair kp = hpke.generatePrivateKey();
            byte[][] output = hpke.seal(kp.getPublic(), "info".getBytes(), "aad".getBytes(), "message".getBytes(), null, null, null);
            byte[] ct = output[0];
            byte[] encap = output[1];

            assertEquals("enc size mismatch", hpke.getEncSize(), encap.length);

            byte[] message = hpke.open(encap, kp, "info".getBytes(), "aad".getBytes(), ct, null, null, null);
            assertTrue("Failed", Arrays.areEqual(message, "message".getBytes()));

            try
            {
                byte[] brokenCt = Arrays.concatenate(ct, "eh".getBytes());
                hpke.open(encap, kp, "info".getBytes(), "aad".getBytes(), brokenCt, null, null, null);
                fail("no exception");
            }
            catch (InvalidCipherTextException e)
            {
                assertEquals("Failed", "mac check in GCM failed", e.getMessage());
            }
        }
    }

    public void testPQKemPSKPairwise()
        throws Exception
    {
        for (int i = 0; i != PQ_KEM_IDS.length; i++)
        {
            HPKE hpke = new HPKE(HPKE.mode_psk, PQ_KEM_IDS[i], HPKE.kdf_HKDF_SHA256, HPKE.aead_CHACHA20_POLY1305);

            AsymmetricCipherKeyPair kp = hpke.generatePrivateKey();

            HPKEContextWithEncapsulation ctxS = hpke.SetupPSKS(kp.getPublic(), "info".getBytes(), "psk".getBytes(), "psk_id".getBytes());
            HPKEContext ctxR = hpke.setupPSKR(ctxS.getEncapsulation(), kp, "info".getBytes(), "psk".getBytes(), "psk_id".getBytes());

            for (int j = 0; j != 3; j++)
            {
                byte[] ct = ctxS.seal("aad".getBytes(), "message".getBytes());
                byte[] message = ctxR.open("aad".getBytes(), ct);
                assertTrue("Failed", Arrays.areEqual(message, "message".getBytes()));
            }

            assertTrue("export mismatch", Arrays.areEqual(
                ctxS.export("ctx".getBytes(), 32), ctxR.export("ctx".getBytes(), 32)));
        }
    }

    public void testPQKemSerialization()
        throws Exception
    {
        for (int i = 0; i != PQ_KEM_IDS.length; i++)
        {
            HPKE hpke = new HPKE(HPKE.mode_base, PQ_KEM_IDS[i], HPKE.kdf_HKDF_SHA256, HPKE.aead_AES_GCM128);

            AsymmetricCipherKeyPair kp = hpke.generatePrivateKey();

            byte[] pkEnc = hpke.serializePublicKey(kp.getPublic());
            byte[] skEnc = hpke.serializePrivateKey(kp.getPrivate());

            // public key round trip
            AsymmetricKeyParameter pk = hpke.deserializePublicKey(pkEnc);
            assertTrue("public key round trip failed", Arrays.areEqual(pkEnc, hpke.serializePublicKey(pk)));

            // private key round trip (with and without the public half)
            AsymmetricCipherKeyPair kp2 = hpke.deserializePrivateKey(skEnc, pkEnc);
            assertTrue("private key round trip failed", Arrays.areEqual(skEnc, hpke.serializePrivateKey(kp2.getPrivate())));
            assertTrue("public half mismatch", Arrays.areEqual(pkEnc, hpke.serializePublicKey(kp2.getPublic())));

            AsymmetricCipherKeyPair kp3 = hpke.deserializePrivateKey(skEnc, null);
            assertTrue("recovered public half mismatch", Arrays.areEqual(pkEnc, hpke.serializePublicKey(kp3.getPublic())));

            // seal to the original public key, open with the deserialized private key
            byte[][] output = hpke.seal(pk, "info".getBytes(), "aad".getBytes(), "message".getBytes(), null, null, null);
            byte[] message = hpke.open(output[1], kp2, "info".getBytes(), "aad".getBytes(), output[0], null, null, null);
            assertTrue("Failed", Arrays.areEqual(message, "message".getBytes()));
        }
    }

    public void testPQKemDeriveKeyPair()
        throws Exception
    {
        SecureRandom random = new SecureRandom();

        for (int i = 0; i != PQ_KEM_IDS.length; i++)
        {
            HPKE hpke = new HPKE(HPKE.mode_base, PQ_KEM_IDS[i], HPKE.kdf_HKDF_SHA256, HPKE.aead_AES_GCM128);

            byte[] ikm = new byte[64];
            random.nextBytes(ikm);

            AsymmetricCipherKeyPair kp1 = hpke.deriveKeyPair(ikm);
            AsymmetricCipherKeyPair kp2 = hpke.deriveKeyPair(ikm);

            assertTrue("derived public keys differ", Arrays.areEqual(
                hpke.serializePublicKey(kp1.getPublic()), hpke.serializePublicKey(kp2.getPublic())));
            assertTrue("derived private keys differ", Arrays.areEqual(
                hpke.serializePrivateKey(kp1.getPrivate()), hpke.serializePrivateKey(kp2.getPrivate())));

            if (PQ_KEM_IDS[i] != HPKE.kem_X_WING)
            {
                // for ML-KEM the ikm is the (d, z) seed, which is also the private key encoding
                assertTrue("ML-KEM private key encoding should be the ikm seed",
                    Arrays.areEqual(ikm, hpke.serializePrivateKey(kp1.getPrivate())));
            }
        }
    }

    public void testPQKemAuthModesUnsupported()
        throws Exception
    {
        for (int i = 0; i != PQ_KEM_IDS.length; i++)
        {
            HPKE hpke = new HPKE(HPKE.mode_auth, PQ_KEM_IDS[i], HPKE.kdf_HKDF_SHA256, HPKE.aead_AES_GCM128);

            AsymmetricCipherKeyPair kpR = hpke.generatePrivateKey();
            AsymmetricCipherKeyPair kpS = hpke.generatePrivateKey();

            try
            {
                hpke.seal(kpR.getPublic(), "info".getBytes(), "aad".getBytes(), "message".getBytes(), null, null, kpS);
                fail("no exception");
            }
            catch (UnsupportedOperationException e)
            {
                // expected - not an authenticated KEM
            }
        }
    }

    public void testXWingHPKEVector()
        throws Exception
    {
        HPKE hpke = new HPKE(HPKE.mode_base, HPKE.kem_X_WING, HPKE.kdf_HKDF_SHA256, HPKE.aead_AES_GCM128);

        // the X-Wing private key encoding is its 32-byte seed
        AsymmetricCipherKeyPair kpR = hpke.deserializePrivateKey(xwingSeed, null);
        assertTrue("X-Wing public key mismatch", Arrays.areEqual(xwingPub, hpke.serializePublicKey(kpR.getPublic())));

        // deterministic encapsulation using the draft's eseed must reproduce the draft's ct
        AsymmetricKeyParameter pkR = hpke.deserializePublicKey(xwingPub);
        HPKEContextWithEncapsulation ctxS = hpke.setupBaseS(pkR, "info".getBytes(), xwingEseed);
        assertTrue("X-Wing encapsulation mismatch", Arrays.areEqual(xwingCt, ctxS.getEncapsulation()));

        // both ends must agree on the derived context
        HPKEContext ctxR = hpke.setupBaseR(ctxS.getEncapsulation(), kpR, "info".getBytes());

        byte[] ct = ctxS.seal("aad".getBytes(), "message".getBytes());
        byte[] message = ctxR.open("aad".getBytes(), ct);
        assertTrue("Failed", Arrays.areEqual(message, "message".getBytes()));

        assertTrue("export mismatch", Arrays.areEqual(
            ctxS.export("ctx".getBytes(), 32), ctxR.export("ctx".getBytes(), 32)));
    }

    public void testVectors()
            throws Exception
    {
        InputStream src = TestResourceFinder.findTestResource("crypto", "hpke.txt");
        BufferedReader bin = new BufferedReader(new InputStreamReader(src));
        String line = null;
        HashMap<String, String> buf = new HashMap<String, String>();
        HashMap<String, String> encBuf = new HashMap<String, String>();
        HashMap<String, String> expBuf = new HashMap<String, String>();
        ArrayList<Encryption> encryptions = new ArrayList<Encryption>();
        ArrayList<Export> exports = new ArrayList<Export>();
        while ((line = bin.readLine()) != null)
        {
            line = line.trim();

            if (line.length() == 0)
            {
                if (buf.size() > 0)
                {
                    String count = (String)buf.get("count");

                    byte mode = Byte.parseByte((String)buf.get("mode"));
                    short kem_id = Short.parseShort((String)buf.get("kem_id"));
                    short kdf_id = Short.parseShort((String)buf.get("kdf_id"));
                    short aead_id = (short) Integer.parseInt((String)buf.get("aead_id"));
                    byte[] info = Hex.decode((String)buf.get("info"));
                    byte[] ikmR = Hex.decode((String)buf.get("ikmR"));
                    byte[] ikmS = null;    // -> mode 2, 3
                    byte[] ikmE = Hex.decode((String)buf.get("ikmE"));
                    byte[] skRm = Hex.decode((String)buf.get("skRm"));
                    byte[] skSm = null;    // -> mode 2, 3
                    byte[] skEm = Hex.decode((String)buf.get("skEm"));
                    byte[] psk = null;     // -> mode 1, 3
                    byte[] psk_id = null;  // -> mode 1, 3
                    byte[] pkRm = Hex.decode((String)buf.get("pkRm"));
                    byte[] pkSm = null;    // -> mode 2, 3
                    byte[] pkEm = Hex.decode((String)buf.get("pkEm"));
                    byte[] enc = Hex.decode((String)buf.get("enc"));
                    byte[] shared_secret = Hex.decode((String)buf.get("shared_secret"));
                    byte[] key_schedule_context = Hex.decode((String)buf.get("key_schedule_context"));
                    byte[] secret = Hex.decode((String)buf.get("secret"));
                    byte[] key = Hex.decode((String)buf.get("key"));
                    byte[] base_nonce = Hex.decode((String)buf.get("base_nonce"));
                    byte[] exporter_secret = Hex.decode((String)buf.get("exporter_secret"));
                    if (mode == 2 || mode == 3)
                    {
                        ikmS = Hex.decode((String)buf.get("ikmS"));
                        skSm = Hex.decode((String)buf.get("skSm"));
                        pkSm = Hex.decode((String)buf.get("pkSm"));
                    }
                    if (mode == 1 || mode == 3)
                    {
                        psk = Hex.decode((String)buf.get("psk"));
                        psk_id = Hex.decode((String)buf.get("psk_id"));
                    }

                    //System.out.print.println("test case: " + count);
//                    System.out.println("mode: " + mode + " kemID: " + kem_id + " kdfID: " + kdf_id + " aeadID: " + aead_id);

                    HPKE hpke = new HPKE(mode, kem_id, kdf_id, aead_id);

                    // Testing AEAD ( encryptions )

                    // init aead with key and nonce
                    AEAD aead = new AEAD(aead_id, key, base_nonce);
                    // enumerate encryptions
                    for (Iterator it = encryptions.iterator(); it.hasNext();)
                    {
                        Encryption encryption = (Encryption)it.next();

                        // seal with aad and pt and check if output is the same as ct
                        byte[] got_ct = aead.seal(encryption.aad, encryption.pt);
                        assertTrue( "AEAD failed Sealing:", Arrays.areEqual(got_ct, encryption.ct));
                    }

                    // Testing main ( different modes )

                    // generate key pair from ikmR ( should be the same as below )
                    AsymmetricCipherKeyPair derivedKeyPairR = hpke.deriveKeyPair(ikmR);
                    // generate a private key from skRm and pkRm
                    AsymmetricCipherKeyPair kp = hpke.deserializePrivateKey(skRm, pkRm);

                    byte[] skRm_serialized = Arrays.clone(skRm);
                    byte[] skSm_serialized = Arrays.clone(skSm);
                    byte[] skEm_serialized = Arrays.clone(skEm);

                    switch (kem_id)
                    {
                    case HPKE.kem_X25519_SHA256:
                        X25519.clampPrivateKey(skRm_serialized);
                        if (mode == 2 || mode == 3)
                        {
                            X25519.clampPrivateKey(skSm_serialized);
                        }
                        X25519.clampPrivateKey(skEm_serialized);
                        break;
                    case HPKE.kem_X448_SHA512:
                        X448.clampPrivateKey(skRm_serialized);
                        if (mode == 2 || mode == 3)
                        {
                            X448.clampPrivateKey(skSm_serialized);
                        }
                        X448.clampPrivateKey(skEm_serialized);
                        break;
                    }

                    // tesing serialize
                    assertTrue("serialize public key failed", Arrays.areEqual(pkRm, hpke.serializePublicKey(kp.getPublic())));
                    assertTrue("serialize private key failed", Arrays.areEqual(skRm_serialized, hpke.serializePrivateKey(kp.getPrivate())));

                    // testing receiver derive key pair
                    assertTrue("receiver derived public key pair incorrect", Arrays.areEqual(pkRm, hpke.serializePublicKey(derivedKeyPairR.getPublic())));
                    assertTrue("receiver derived secret key pair incorrect", Arrays.areEqual(skRm_serialized, hpke.serializePrivateKey(derivedKeyPairR.getPrivate())));

                    // testing sender's derived key pair
                    if (mode == 2 || mode == 3)
                    {
                        AsymmetricCipherKeyPair derivedSenderKeyPair = hpke.deriveKeyPair(ikmS);
                        assertTrue("sender derived public key pair incorrect", Arrays.areEqual(pkSm, hpke.serializePublicKey(derivedSenderKeyPair.getPublic())));
                        assertTrue("sender derived private key pair incorrect", Arrays.areEqual(skSm_serialized, hpke.serializePrivateKey(derivedSenderKeyPair.getPrivate())));
                    }

                    // testing ephemeral derived key pair
                    AsymmetricCipherKeyPair derivedEKeyPair = hpke.deriveKeyPair(ikmE);
                    assertTrue("ephemeral derived public key pair incorrect", Arrays.areEqual(pkEm, hpke.serializePublicKey(derivedEKeyPair.getPublic())));
                    assertTrue("ephemeral derived private key pair incorrect", Arrays.areEqual(skEm_serialized, hpke.serializePrivateKey(derivedEKeyPair.getPrivate())));

                    // create a context with setupRecv
                    // use pkEm as encap, private key from above, info as info

                    HPKEContext c = null;
                    AsymmetricKeyParameter senderPub = null;
                    switch (mode)
                    {
                        case 0:
                            c = hpke.setupBaseR(pkEm, kp, info);
                            break;
                        case 1:
                            c = hpke.setupPSKR(pkEm, kp, info, psk, psk_id);
                            break;
                        case 2:
                            senderPub = hpke.deserializePublicKey(pkSm);
                            c = hpke.setupAuthR(pkEm, kp, info, senderPub);
                            break;
                        case 3:
                            senderPub = hpke.deserializePublicKey(pkSm);
                            c = hpke.setupAuthPSKR(pkEm, kp, info, psk, psk_id, senderPub);
                            break;
                        default:
                            fail("invalid mode");
                    }

                    // enumerate encryptions
                    for (int i = 0; i < encryptions.size(); i++)
                    {
                        Encryption encryption = (Encryption)encryptions.get(i);

                        if (i == 0)
                        {
                            // test one shot api (first only!)
                            // open with pkEm, private key, info, aad, ct
                            // compare output with pt
                            byte[] message = hpke.open(pkEm, kp, info, encryption.aad, encryption.ct, psk, psk_id, senderPub);

                            // use context open with aad, ct and compare output with pt
                            assertTrue("Single-shot failed", Arrays.areEqual(message, encryption.pt));
                        }

                        byte[] got_pt = c.open(encryption.aad, encryption.ct);
                        assertTrue("context failed Open", Arrays.areEqual(got_pt, encryption.pt));
                    }

                    // enumerate exports
                    for (Iterator it = exports.iterator(); it.hasNext();)
                    {
                        Export export = (Export)it.next();
                        // use context export with exporter context and L
                        byte[] got_val = c.export(export.exporterContext, export.L);

                        // compare output with exported value
                        assertTrue("context failed Open", Arrays.areEqual(got_val, export.exportedValue));
                    }

                }
                buf.clear();
                encryptions.clear();
                exports.clear();

                continue;
            }

            int a = line.indexOf("=");
            if (a > -1)
            {
                buf.put(line.substring(0, a).trim(), line.substring(a + 1).trim());
            }
            if (line.equals("encryptionsSTART"))
            {
                while ((line = bin.readLine()) != null)
                {
                    line = line.trim();
                    if (line.equals("encryptionsSTOP"))
                    {
                        break;
                    }
                    if (line.equals("<"))
                    {
                        byte[] aad = Hex.decode((String)encBuf.get("aad"));
                        byte[] ct = Hex.decode((String)encBuf.get("ct"));
                        byte[] nonce = Hex.decode((String)encBuf.get("nonce"));
                        byte[] pt = Hex.decode((String)encBuf.get("pt"));
                        encryptions.add(new Encryption(aad, ct, nonce, pt));
                        encBuf.clear();
                    }
                    else
                    {
                        int b = line.indexOf("=");
                        if (b > -1)
                        {
                            encBuf.put(line.substring(0, b).trim(), line.substring(b + 1).trim());
                        }
                    }
                }
            }

            if (line.equals("exportsSTART"))
            {
                while ((line = bin.readLine()) != null)
                {
                    line = line.trim();
                    if (line.equals("exportsSTOP"))
                    {
                        break;
                    }
                    if (line.equals("<"))
                    {
                        byte[] exporterContext = Hex.decode((String) expBuf.get("exporter_context"));
                        int L = Integer.parseInt((String)expBuf.get("L"));
                        byte[] exportedValue = Hex.decode((String) expBuf.get("exported_value"));
                        exports.add(new Export(exporterContext, L, exportedValue));
                        expBuf.clear();
                    }
                    else
                    {
                        int b = line.indexOf("=");
                        if (b > -1)
                        {
                            expBuf.put(line.substring(0, b).trim(), line.substring(b + 1).trim());
                        }
                    }
                }
            }
        }
        //System.out.print.println("testing successful!");

    }
}
