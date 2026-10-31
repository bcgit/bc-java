package org.bouncycastle.crypto.signers.lms;

import java.security.SecureRandom;

import junit.framework.TestCase;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.HSSKeyPairGenerator;
import org.bouncycastle.crypto.generators.LMSKeyPairGenerator;
import org.bouncycastle.crypto.params.HSSKeyGenerationParameters;
import org.bouncycastle.crypto.params.HSSPrivateKeyParameters;
import org.bouncycastle.crypto.params.LMOtsParameters;
import org.bouncycastle.crypto.params.LMSKeyGenerationParameters;
import org.bouncycastle.crypto.params.LMSParameters;
import org.bouncycastle.crypto.params.LMSigParameters;
import org.bouncycastle.crypto.signers.HSSSigner;
import org.bouncycastle.crypto.signers.LMSSigner;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.FixedSecureRandom;

/**
 * Known answers recorded from the org.bouncycastle.pqc.crypto.lms implementation this one was
 * promoted from, before that package was removed. While both shipped, a test compared the two byte
 * for byte; these SHA-256 digests of the SubjectPublicKeyInfo, PrivateKeyInfo and signature
 * encodings it produced from fixed seeds are what is left of that comparison. They cover every
 * LMS/LM-OTS pairing of the original test's matrix, a two level HSS key, every index of an LMS key,
 * and an HSS key signed across its first bottom-tree boundary together with the private key
 * encoding that carries its index state afterwards.
 */
public class PromotionKnownAnswerTests
    extends TestCase
{
    private static final byte[] MESSAGE = Strings.toByteArray("the quick brown fox jumped over the lazy dog");

    private static final LMSigParameters[] SIG =
        {
            LMSigParameters.lms_sha256_n32_h5,
            LMSigParameters.lms_sha256_n32_h10,
            LMSigParameters.lms_sha256_n24_h5,
            LMSigParameters.lms_shake256_n32_h5,
            LMSigParameters.lms_shake256_n24_h5
        };

    private static final LMOtsParameters[] OTS =
        {
            LMOtsParameters.sha256_n32_w1,
            LMOtsParameters.sha256_n32_w2,
            LMOtsParameters.sha256_n32_w4,
            LMOtsParameters.sha256_n32_w8
        };

    private static final String[][] VECTORS = {
        { "LMS 5/1", "pub", "f5ec6a0fe9bbbfa37f551b2362d6d97aeb302dab32a3e39d2b12362fb0021ba8" },
        { "LMS 5/1", "priv", "5f958d5d2e1083e9e551f08ed54550f4f8f87d5a4c4535f625566ac384e79bfc" },
        { "LMS 5/1", "sig", "e32c642244068d6a0a25bdac823cf020a694b6d46a33b2e402e4f66ddbd0b6c0" },
        { "LMS 5/2", "pub", "460c17327ad2f8d17731ecd86ed4cf1eb540eabfe3cabf3200d0dda8ec6c79e7" },
        { "LMS 5/2", "priv", "80234c7806801c65626122b43528fd5f8cb3b77d6467a5195044880aefab21fa" },
        { "LMS 5/2", "sig", "5870c496cbcb1746f4b00f9efbf962b7f9879978c33e9be54ae47681b9f107cc" },
        { "LMS 5/3", "pub", "15b5c88c3d0322f3123f9888b1651a8fc34e50c42739fdc821ea81a491e9b892" },
        { "LMS 5/3", "priv", "0a9d6ad36f5cbb9ceb8e7896f58a89b177b6d5fbd31f280423480edf0fffc7cb" },
        { "LMS 5/3", "sig", "bd9f0dbbb32cb29917422e2f8125cd5c3a9374a4e3f5570f7e2050e33d12a326" },
        { "LMS 5/4", "pub", "f9c6768390ef5d23f824ab96cf0f7e6233004c6c417d7f1546d51e30cddb5e88" },
        { "LMS 5/4", "priv", "ce60ad3de9e27af270a8fd136c2642440e7363d499f71e6858e272502fefb153" },
        { "LMS 5/4", "sig", "3e49e330afc96b74dc6b161ef13f646336ced4b19205a4f3fd130467b70b287f" },
        { "LMS 6/1", "pub", "e09e73e681d4548b668cf564bfa69871b37eb59e5fef214e741b8e4470133cc6" },
        { "LMS 6/1", "priv", "846bd1d39140a9d6472a59752284c7cba5f7b691e202cfe17331aea29abebd04" },
        { "LMS 6/1", "sig", "88e7aec5bd98ceb9779fffe1c99774862175ae4c5da32023922534a40d3b88a6" },
        { "LMS 6/2", "pub", "58a9ec99bfdf89d0c29e91a3bbc0ef7e5b1ba008921b1fb9c3d7b27ff9ec6f31" },
        { "LMS 6/2", "priv", "b719d0d50e71155026d0d16113f5398246236c44c082a62d5d8d128d325857c9" },
        { "LMS 6/2", "sig", "3bcda9b8cc57415088a1377fca40c96123c38bc0a4e85d602343da4eb0ee8334" },
        { "LMS 6/3", "pub", "541844038a306fb7f5ba5dc3bcf0ffaa76125fe0e903080059e6be0739295ba4" },
        { "LMS 6/3", "priv", "6f0a8eb8073746aea8c8fbe515978838e1d7720f0f49c331b9dfe3579147c469" },
        { "LMS 6/3", "sig", "a335b9dab8eec10dd69f44547cdbbfe6ac26d4dc60aa80a329f3ebeddcc5b9b2" },
        { "LMS 6/4", "pub", "7f226df24a8c6e46f36ced16523d8c70cd1675bcca7ff086d309290dd2a3a297" },
        { "LMS 6/4", "priv", "9675171195776a719290ec756fd1060908d36fd06ad339e0bb145b9ef90e14fb" },
        { "LMS 6/4", "sig", "f4ce8fddd9e69ad98dcc068699bb279108506412c40af2dfa5b96df6ae193c28" },
        { "LMS 10/1", "pub", "eaa5b36f1c5ec58b068a619ab47fae7afd87e120bc9434e0bf06de0d6788ae75" },
        { "LMS 10/1", "priv", "b96030e6f7b5e5c8738ff83592762458ad21c5155e0ba6a7df12c0066768540e" },
        { "LMS 10/1", "sig", "5c8cbc4b67303e783d2e303aecde3c8eaa954d9b6becacf1a0f1e540d61284da" },
        { "LMS 10/2", "pub", "ef4ecde213f138489063106b8b3d81f96cd4ab63399be4c15366a99daf0d877d" },
        { "LMS 10/2", "priv", "3817a10b924399347d6d466f203813b4833b03f5e5cf93ebb0800d3423485042" },
        { "LMS 10/2", "sig", "b557aa83dd9461cdfd3512e614c905e1e5ee2399ae84662838bed9c4d34eda2b" },
        { "LMS 10/3", "pub", "8d6843f865f41947fe8afaca7808f67b519a3dc5605792aab51db3382319d973" },
        { "LMS 10/3", "priv", "2ffa26a1cfed0cdf1c1fe99b87c7ea910f3588205a61ee62bb42cc750aa3c3a9" },
        { "LMS 10/3", "sig", "7787b34618291a950b63a6e6384fbf8f0e6b23410969dd167f39d1d1661c0174" },
        { "LMS 10/4", "pub", "14a8cd7d9d13da6f507fa117d726d7c4c352f174462ec9c3fd1fae8faa03752e" },
        { "LMS 10/4", "priv", "f0f1b9255751ce33a88a4a827b77f63661615ba9becc2d69fd99abb7559339cb" },
        { "LMS 10/4", "sig", "d046431a7f213d4ed540de66bc45059331c3b9c1f7b65de561d651fe136e0440" },
        { "LMS 15/1", "pub", "0a4209fe64497d5b42615dc54f3bb2686a7229a818517471dbdc95571f746f9d" },
        { "LMS 15/1", "priv", "df7da1f68488c08131932d411b1687e2a49bbe3a6fe86d0d7e3244d0d7af1d28" },
        { "LMS 15/1", "sig", "5b1c1ab938ac264906e27ec94d5436767942704c617ffc15ceb36d3fbd985c7d" },
        { "LMS 15/2", "pub", "6782f1bf8a896a7964f7b74988abcb7c4213690031105421d5e036116c30e6ce" },
        { "LMS 15/2", "priv", "015e5d59779e2ae27522a6b1d8469eb223449b3694898cd4dbb86ac2cc7033d2" },
        { "LMS 15/2", "sig", "f892e027caa21b12dd6f7a3562cbf8fe2b9cbf2be2bef8553ddf02d6b8f51f00" },
        { "LMS 15/3", "pub", "95b2d67058322b4caf715c025f89a90f03c291316e0e10c4a1dc34536b3b62a6" },
        { "LMS 15/3", "priv", "43ed41ec4ad0cf695b3bc918c4c43d299623273449ba1ebf2bbbb54724cb57b7" },
        { "LMS 15/3", "sig", "fc47f06b8ff5c160ce38186c678d7ad4cc96570b89248ff3b29e7883a0467a14" },
        { "LMS 15/4", "pub", "00a4872681256f92982e35fd11b7d51627fa11a2504f320d5982023fdab8f5d3" },
        { "LMS 15/4", "priv", "7c9665bff8be705bcbb304e61748063e134ba7c88aa9d6875054606e69e09ef4" },
        { "LMS 15/4", "sig", "27cf3a36dec97eafb76636eb08d50f88e8cba90f4297d871cbebd3178b745d33" },
        { "LMS 20/1", "pub", "300f4e4afd293f65d743bdd672e05cadbca2ead5bee85ebb46e63d2d74af7fe8" },
        { "LMS 20/1", "priv", "0af35bdf5e587ce2d6eb28790f55e09d8a16cf719ba92a9cc73ccce4c3be35a3" },
        { "LMS 20/1", "sig", "8f912a85bbf4a5117bbeb07a672b86998f41ff3a79bfebeab558b02744d1af7e" },
        { "LMS 20/2", "pub", "bf528e433d398c8c5bde756605958691cf33cbdc5fc958ae4bbef66afd3708c4" },
        { "LMS 20/2", "priv", "474b4fa24e66a78cd79ad4064f3369006d3bc825bbccc245603426924054224c" },
        { "LMS 20/2", "sig", "0d0159efcd3e8f86bbc52792706a2a2ebde6e4868b8e9f182dc2ca2578793587" },
        { "LMS 20/3", "pub", "9ccdaa0359c8c1497c40f5b710231c5ccd3b43f860723b907c046edec59b04bf" },
        { "LMS 20/3", "priv", "1393e0975cded0f71f5833822f5ccc73e7742dbb5ea4081f53748f4bb15937d5" },
        { "LMS 20/3", "sig", "a2d1218b71b82ce107c02283b53d2a4ca4ac1202c472949e6e6f4207bf928af4" },
        { "LMS 20/4", "pub", "4f8f51d99c433704a79f8f550f6676a8940af57e2db9d5f45af0be1985301ddf" },
        { "LMS 20/4", "priv", "11bbdb3383e174bfb4d4d473529508efc3b667b30706bbbcefbab86e79286720" },
        { "LMS 20/4", "sig", "82bc6d3473f095494dc8efbe7dc38fc4a09eb048e1229ad9d40d99712aed937b" },
        { "HSS", "pub", "43922bd9deb48a73975823e57a4fa39120040df315c6bec36b463c80e75903ee" },
        { "HSS", "priv", "f6dfa2d5044362746f256dfc4035779246d20a509531ce55d57661b42213738a" },
        { "HSS", "sig", "ee41ddadbdf48fb34503ccd046213ec56994004f9d94b806f8e439c06a2862c1" },
        { "LMS every index", "sigs", "7b1d342d3e9e81fa067c86b036ec39b6a87a2c73e96dcb4eaf9ea0aa81d3ebf0" },
        { "HSS first 40 indices", "sigs", "f3abbb84ca6c44588086cd6716d7b6577cde37f95a25254c28905fb93b488d5f" },
        { "HSS first 40 indices", "priv", "c8424262fb3b13b5b326f04c36a3cb435e2e477d9f21471377e20d0d0f2630e9" }
    };

    public void testLMSKeysAndSignatures()
        throws Exception
    {
        for (int i = 0; i != SIG.length; i++)
        {
            for (int j = 0; j != OTS.length; j++)
            {
                String label = "LMS " + SIG[i].getType() + "/" + OTS[j].getType();
                AsymmetricCipherKeyPair kp = lmsKey(SIG[i], OTS[j], seedFor(i * OTS.length + j));

                checkEncodings(label, kp);

                LMSSigner signer = new LMSSigner();
                signer.init(true, kp.getPrivate());
                byte[] sig = signer.generateSignature(MESSAGE);
                assertEquals(label + ": signature", expected(label, "sig"), sha256(sig));

                LMSSigner verifier = new LMSSigner();
                verifier.init(false, kp.getPublic());
                assertTrue(label + ": signature did not verify", verifier.verifySignature(MESSAGE, sig));
            }
        }
    }

    public void testHSSKeysAndSignatures()
        throws Exception
    {
        AsymmetricCipherKeyPair kp = hssKey(seedFor(99));

        checkEncodings("HSS", kp);

        HSSSigner signer = new HSSSigner();
        signer.init(true, kp.getPrivate());
        byte[] sig = signer.generateSignature(MESSAGE);
        assertEquals("HSS: signature", expected("HSS", "sig"), sha256(sig));

        HSSSigner verifier = new HSSSigner();
        verifier.init(false, kp.getPublic());
        assertTrue("HSS: signature did not verify", verifier.verifySignature(MESSAGE, sig));
    }

    public void testSignaturesAcrossIndices()
        throws Exception
    {
        LMSSigner signer = new LMSSigner();
        signer.init(true, lmsKey(SIG[0], OTS[2], seedFor(40)).getPrivate());

        SHA256Digest all = new SHA256Digest();
        for (int i = 0; i != 1 << 5; i++)
        {
            byte[] sig = signer.generateSignature(MESSAGE);
            all.update(sig, 0, sig.length);
        }
        assertEquals("LMS: signatures over every index", expected("LMS every index", "sigs"), doFinal(all));

        AsymmetricCipherKeyPair kp = hssKey(seedFor(41));
        HSSSigner hssSigner = new HSSSigner();
        hssSigner.init(true, kp.getPrivate());

        all = new SHA256Digest();
        for (int i = 0; i != 40; i++)
        {
            byte[] sig = hssSigner.generateSignature(MESSAGE);
            all.update(sig, 0, sig.length);
        }
        assertEquals("HSS: signatures over the first 40 indices", expected("HSS first 40 indices", "sigs"), doFinal(all));
        assertEquals("HSS: private key after 40 signatures", expected("HSS first 40 indices", "priv"),
            sha256(PrivateKeyInfoFactory.createPrivateKeyInfo(kp.getPrivate()).getEncoded()));
    }

    /**
     * The promoted signers implement org.bouncycastle.crypto.Signer rather than the pqc
     * MessageSigner, so the streaming path must produce what the one-shot call verifies.
     */
    public void testStreamingMatchesOneShot()
        throws Exception
    {
        AsymmetricCipherKeyPair kp = lmsKey(SIG[0], OTS[0], seedFor(7));

        LMSSigner signer = new LMSSigner();
        signer.init(true, kp.getPrivate());
        signer.update(MESSAGE, 0, MESSAGE.length);
        byte[] streamed = signer.generateSignature();

        LMSSigner verifier = new LMSSigner();
        verifier.init(false, kp.getPublic());
        verifier.update(MESSAGE, 0, MESSAGE.length);
        assertTrue("streamed signature did not verify through the streaming path",
            verifier.verifySignature(streamed));

        // verifySignature() consumed the buffer, so the one-shot form verifies the message alone
        verifier.init(false, kp.getPublic());
        assertTrue("streamed signature did not verify one-shot", verifier.verifySignature(MESSAGE, streamed));
    }

    private void checkEncodings(String label, AsymmetricCipherKeyPair kp)
        throws Exception
    {
        byte[] pub = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(kp.getPublic()).getEncoded();
        byte[] priv = PrivateKeyInfoFactory.createPrivateKeyInfo(kp.getPrivate()).getEncoded();

        assertEquals(label + ": public key encoding", expected(label, "pub"), sha256(pub));
        assertEquals(label + ": private key encoding", expected(label, "priv"), sha256(priv));

        // and the encodings read back to keys that encode the same way
        assertTrue(label + ": public key did not round trip", Arrays.areEqual(pub,
            SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(PublicKeyFactory.createKey(pub)).getEncoded()));

        // an LMS private key reads back as the equivalent single level HSS key, so for LMS the
        // second encoding is the HSS one; it must carry the same public key and be stable from there
        HSSPrivateKeyParameters decoded = (HSSPrivateKeyParameters)PrivateKeyFactory.createKey(priv);
        assertTrue(label + ": private key read back with a different public key", Arrays.areEqual(pub,
            SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(decoded.getPublicKey()).getEncoded()));

        byte[] reEncoded = PrivateKeyInfoFactory.createPrivateKeyInfo(decoded).getEncoded();
        if (kp.getPrivate() instanceof HSSPrivateKeyParameters)
        {
            assertTrue(label + ": private key did not round trip", Arrays.areEqual(priv, reEncoded));
        }
        assertTrue(label + ": private key encoding not stable", Arrays.areEqual(reEncoded,
            PrivateKeyInfoFactory.createPrivateKeyInfo(PrivateKeyFactory.createKey(reEncoded)).getEncoded()));
    }

    private static String expected(String label, String what)
    {
        for (int i = 0; i != VECTORS.length; i++)
        {
            if (VECTORS[i][0].equals(label) && VECTORS[i][1].equals(what))
            {
                return VECTORS[i][2];
            }
        }
        throw new IllegalStateException("no vector for " + label + " " + what);
    }

    private static String sha256(byte[] data)
    {
        SHA256Digest digest = new SHA256Digest();
        digest.update(data, 0, data.length);
        return doFinal(digest);
    }

    private static String doFinal(SHA256Digest digest)
    {
        byte[] out = new byte[digest.getDigestSize()];
        digest.doFinal(out, 0);
        return Hex.toHexString(out);
    }

    private static AsymmetricCipherKeyPair lmsKey(LMSigParameters sig, LMOtsParameters ots, byte[] seed)
    {
        LMSKeyPairGenerator gen = new LMSKeyPairGenerator();
        gen.init(new LMSKeyGenerationParameters(new LMSParameters(sig, ots), fixedRandom(seed)));
        return gen.generateKeyPair();
    }

    private static AsymmetricCipherKeyPair hssKey(byte[] seed)
    {
        HSSKeyPairGenerator gen = new HSSKeyPairGenerator();
        gen.init(new HSSKeyGenerationParameters(new LMSParameters[]
            {
                new LMSParameters(SIG[0], OTS[0]),
                new LMSParameters(SIG[0], OTS[1])
            }, fixedRandom(seed)));
        return gen.generateKeyPair();
    }

    private static byte[] seedFor(int n)
    {
        byte[] seed = new byte[64];
        for (int i = 0; i != seed.length; i++)
        {
            seed[i] = (byte)(n * 31 + i);
        }
        return seed;
    }

    private static SecureRandom fixedRandom(byte[] seed)
    {
        return new FixedSecureRandom(
            new FixedSecureRandom.Source[]{ new FixedSecureRandom.Data(Arrays.concatenate(seed, seed, seed, seed)) });
    }
}
