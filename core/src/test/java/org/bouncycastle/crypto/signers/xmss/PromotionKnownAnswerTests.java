package org.bouncycastle.crypto.signers.xmss;

import java.security.SecureRandom;

import junit.framework.TestCase;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.crypto.generators.XMSSKeyPairGenerator;
import org.bouncycastle.crypto.generators.XMSSMTKeyPairGenerator;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.params.XMSSKeyGenerationParameters;
import org.bouncycastle.crypto.params.XMSSMTKeyGenerationParameters;
import org.bouncycastle.crypto.params.XMSSMTParameters;
import org.bouncycastle.crypto.params.XMSSParameters;
import org.bouncycastle.crypto.signers.XMSSMTSigner;
import org.bouncycastle.crypto.signers.XMSSSigner;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.FixedSecureRandom;

/**
 * Known answers recorded from the org.bouncycastle.pqc.crypto.xmss implementation this one was
 * promoted from, before that package was removed. While both shipped, a test compared the two byte
 * for byte; these SHA-256 digests of the SubjectPublicKeyInfo, PrivateKeyInfo and signature
 * encodings it produced from fixed seeds are what is left of that comparison, and they still pin
 * what a round trip cannot: the truncating branch of KeyedHashFunctions.coreDigest
 * (XMSS-SHA2_10_192, the one set here whose n is shorter than a non-Xof digest - copying the
 * wrong 24 bytes agrees with itself), the XMSS^MT raw private key layout (XMSSMT-SHA2_20/2_256)
 * and the idx_sig bytes of the H_msg key, which are all zeros at index 0 and show only by signing
 * at every index of a key.
 */
public class PromotionKnownAnswerTests
    extends TestCase
{
    private static final byte[] MESSAGE = Strings.toByteArray("the quick brown fox jumped over the lazy dog");

    private static final String[][] VECTORS = {
        { "XMSS h4/0", "pub", "ce4406b5b89cbaa66b6623dfc14deb5fefad6360ecbe9cc2204b4cd8f15e4203" },
        { "XMSS h4/0", "priv", "06eeae237d8b99eb72ca272c9e4564ea2d3031eff62f8b715613042b568c8c90" },
        { "XMSS h4/0", "sig", "0ea6d588a11e817ee3417e22d12822377a4321306802d6ea9c90b5aa956452c7" },
        { "XMSS h4/1", "pub", "f074b48ae2ee91b411708a51dcd41e63b9c13f9debac6b6853bd35f3039bbaa2" },
        { "XMSS h4/1", "priv", "b88570e9ad602c8f8a8fa389478e2a1c5d62eae827688dac5a7bea18635f7127" },
        { "XMSS h4/1", "sig", "b9dc894a83015b16dc5c4116d097a61b38c70866d3fb59f2fd137f8461a3eca9" },
        { "XMSS h4/2", "pub", "4551b19b0a1370c74d7ea896923f9821f2da3c45828f16ea56a0784fdbb09f5a" },
        { "XMSS h4/2", "priv", "6eaf2d96e1e88d29cb78bb75cf049ea8b2087c2c175e490db64c34bf63f962a1" },
        { "XMSS h4/2", "sig", "6648f1f5db96c36136eb588b3545a9632477d098936df4239384fab683c8ee53" },
        { "XMSS h4/3", "pub", "fbf5c442bb06505307f3cf54cb32ee55b536a271cb805ddcc5c1600ca1fea4ff" },
        { "XMSS h4/3", "priv", "97ee527f3a67da85af0cd08e6c7d3c46fedc58d0599a066ae022399bb8fb2cfe" },
        { "XMSS h4/3", "sig", "153019ff13063a5cc243e5701428896a37a12d6e01d8ffe3bb4fe503963d0a94" },
        { "XMSS-SHA2_10_256", "pub", "0e1451fbae7108893776abb1d0e0b63816d9d49f21f0971531cf73cab4ffc664" },
        { "XMSS-SHA2_10_256", "priv", "5b9771bf00119bc8b312d55f712ea5d5f0bd0b28453b03cad101d05b3605c6a4" },
        { "XMSS-SHA2_10_256", "sig", "3db94d6fde04c1c97c9ac3495f817c4445cdc9846f64ef56ddd28f720eb77104" },
        { "XMSS-SHAKE256_10_192", "pub", "dfb6d56fca58a41a08f2e57b3ebc2a7d7634ec871033c2d6efd01870227e7f3e" },
        { "XMSS-SHAKE256_10_192", "priv", "548a5f76c3fcc8ba13e8feb76faebfd085fe41fd0772243522b7ddc6f5db26e9" },
        { "XMSS-SHAKE256_10_192", "sig", "4aeba363fb045547fb167bec48a9621d18e1d77777af5a458b283e79e7f50757" },
        { "XMSS-SHA2_10_192", "pub", "5c8170f3c76a354dedbc220d83eda14b4b8d9bc56e14473ee678de64b263c813" },
        { "XMSS-SHA2_10_192", "priv", "065efcfcb6e2b2d29eb97173cc5dc75b7608a89c447916f5d7e86e00b93ae231" },
        { "XMSS-SHA2_10_192", "sig", "b5c1968e0582c96fbffc5392643fc6b6dcdd51865942db128c4af72ddff52f18" },
        { "XMSSMT-SHA2_20/2_256", "pub", "b70f6e7ac29ada1b189cf966b16d997572d2a042d4e4e09cd915a4ee7a42f529" },
        { "XMSSMT-SHA2_20/2_256", "priv", "4ca7faa3577eb3eaedfb39491b987c12a17c5a8ed134618a5b4c28d9e000d829" },
        { "XMSSMT h4d2/0", "pub", "faaeee5ff11087b25f6cfb6a98e6736258ecc3072012dd99360975a2dce03326" },
        { "XMSSMT h4d2/0", "priv", "a8c4903b6b8efde72730dd2ae6eb516c3a43e276d10d388580f4b237c795d9ec" },
        { "XMSSMT h4d2/0", "sig", "b35a9b452ef0dfd8245c20f124f85655f023cb606e3669e11934bbd23a4183cd" },
        { "XMSSMT h4d2/1", "pub", "68cccbb5ea3c05ca141f53dd2a8f6bf48107b76849f8753d76edb24e0d53a9c9" },
        { "XMSSMT h4d2/1", "priv", "f1de29988552d42830d53c01c51df1862904545fb449f82a60d59a3f78f089ec" },
        { "XMSSMT h4d2/1", "sig", "1e2a376722c69795d342de555cbdbf741acdac0e83f1de1d2a442f19467e1781" },
        { "XMSSMT h4d2/2", "pub", "1f9a5445c07a0d68b0c3051ec678beded0f153eb2016bede2eeba716ba5054cb" },
        { "XMSSMT h4d2/2", "priv", "054105e5022b4779549fa2bcab69ee53c9d6a84bddbf31448e45c289bdfc0876" },
        { "XMSSMT h4d2/2", "sig", "e6e0f0ca6a41d452f7ed6403f2f42ae45b1883a406b84d01d8013cd764b7a158" },
        { "XMSSMT h4d2/3", "pub", "c9ec1ad96417d62cd425d370bc07c94bd9cc84b87ad63059bcb617c3f7ef232b" },
        { "XMSSMT h4d2/3", "priv", "d7ec952c5d47f879d70d3410ecaac1ab49215bf859d709a4d6dc3491126ad42b" },
        { "XMSSMT h4d2/3", "sig", "a5ba579595a6537dcbe49a6ea10ec1911c53101657e12c1b84999cdbd8724412" },
        { "XMSS h4/0 every index", "sigs", "db4ed4b8404dd238bae9df783759719361072b5585de27ba32e3935c8996f99e" },
        { "XMSSMT h4d2/0 every index", "sigs", "c3b5fb018973b031218b0ed3e4bf0f43e050c3338970105359830d3ebd5de753" },
    };

    public void testXMSSKeysAndSignatures()
        throws Exception
    {
        for (int i = 0; i != 4; i++)
        {
            checkXMSS("XMSS h4/" + i, new XMSSParameters(4, digest(i)), seedFor(i));
        }
    }

    public void testStandardParameterSets()
        throws Exception
    {
        checkXMSS("XMSS-SHA2_10_256", new XMSSParameters(10, new SHA256Digest()), seedFor(10));
        checkXMSS("XMSS-SHAKE256_10_192", new XMSSParameters(10, NISTObjectIdentifiers.id_shake256_len, 24), seedFor(11));
        checkXMSS("XMSS-SHA2_10_192", new XMSSParameters(10, NISTObjectIdentifiers.id_sha256, 24), seedFor(12));

        checkEncodings("XMSSMT-SHA2_20/2_256", xmssMtKey(new XMSSMTParameters(20, 2, new SHA256Digest()), seedFor(13)));
    }

    public void testXMSSMTKeysAndSignatures()
        throws Exception
    {
        for (int i = 0; i != 4; i++)
        {
            String label = "XMSSMT h4d2/" + i;
            AsymmetricCipherKeyPair kp = xmssMtKey(new XMSSMTParameters(4, 2, digest(i)), seedFor(20 + i));

            checkEncodings(label, kp);

            XMSSMTSigner signer = new XMSSMTSigner();
            signer.init(true, kp.getPrivate());
            byte[] sig = XMSSHarnessTests.sign(signer, MESSAGE);
            assertEquals(label + ": signature", expected(label, "sig"), sha256(sig));

            XMSSMTSigner verifier = new XMSSMTSigner();
            verifier.init(false, kp.getPublic());
            assertTrue(label + ": signature did not verify", XMSSHarnessTests.verify(verifier, MESSAGE, sig));
        }
    }

    public void testSignaturesAtEveryIndexOfAKey()
        throws Exception
    {
        XMSSSigner signer = new XMSSSigner();
        signer.init(true, xmssKey(new XMSSParameters(4, digest(0)), seedFor(30)).getPrivate());

        SHA256Digest all = new SHA256Digest();
        for (int i = 0; i != 1 << 4; i++)
        {
            byte[] sig = XMSSHarnessTests.sign(signer, MESSAGE);
            all.update(sig, 0, sig.length);
        }
        assertEquals("XMSS: signatures over every index", expected("XMSS h4/0 every index", "sigs"), doFinal(all));

        XMSSMTSigner mtSigner = new XMSSMTSigner();
        mtSigner.init(true, xmssMtKey(new XMSSMTParameters(4, 2, digest(0)), seedFor(31)).getPrivate());

        all = new SHA256Digest();
        for (int i = 0; i != 1 << 4; i++)
        {
            byte[] sig = XMSSHarnessTests.sign(mtSigner, MESSAGE);
            all.update(sig, 0, sig.length);
        }
        assertEquals("XMSS^MT: signatures over every index", expected("XMSSMT h4d2/0 every index", "sigs"), doFinal(all));
    }

    /**
     * The signers implement org.bouncycastle.crypto.Signer, so a message streamed in through
     * update() must sign and verify, and the buffer must be consumed by each operation rather than
     * carried into the next.
     */
    public void testStreamingRoundTrip()
        throws Exception
    {
        AsymmetricCipherKeyPair kp = xmssKey(new XMSSParameters(4, new SHA256Digest()), seedFor(7));

        XMSSSigner signer = new XMSSSigner();
        signer.init(true, kp.getPrivate());
        signer.update(MESSAGE, 0, MESSAGE.length);
        byte[] streamed = signer.generateSignature();

        XMSSSigner verifier = new XMSSSigner();
        verifier.init(false, kp.getPublic());
        verifier.update(MESSAGE, 0, MESSAGE.length);
        assertTrue("streamed signature did not verify through the streaming path",
            verifier.verifySignature(streamed));

        // verifySignature() consumed the buffer, so feeding the same message again verifies the
        // message alone and not the message twice
        verifier.init(false, kp.getPublic());
        verifier.update(MESSAGE, 0, MESSAGE.length);
        assertTrue("second streamed verification failed", verifier.verifySignature(streamed));
    }

    /**
     * The JCA layer wraps the private key in a ParametersWithRandom whenever a SecureRandom is
     * supplied, so both signers have to accept the wrapper. XMSS derives its randomizer from the key
     * (r = PRF(SK_PRF, toByte(idx, 32)), RFC 8391 sec. 4.1.9 / 4.2.7), so the supplied random has
     * nothing to drive: the signature must come out byte-identical to the one signed without the
     * wrapper, which is what says the random was discarded rather than mixed in.
     */
    public void testParametersWithRandomAcceptedForSigning()
        throws Exception
    {
        // a random that would be impossible to miss had any of it reached the signature
        SecureRandom random = new FixedSecureRandom(
            new FixedSecureRandom.Source[]{ new FixedSecureRandom.Data(new byte[256]) });

        XMSSParameters params = new XMSSParameters(4, digest(0));
        byte[] seed = seedFor(31);

        XMSSSigner wrappedSigner = new XMSSSigner();
        wrappedSigner.init(true, new ParametersWithRandom(xmssKey(params, seed).getPrivate(), random));
        byte[] wrapped = XMSSHarnessTests.sign(wrappedSigner, MESSAGE);

        XMSSSigner plainSigner = new XMSSSigner();
        plainSigner.init(true, xmssKey(params, seed).getPrivate());
        assertTrue("XMSS: ParametersWithRandom changed the signature",
            Arrays.areEqual(wrapped, XMSSHarnessTests.sign(plainSigner, MESSAGE)));

        XMSSMTParameters mtParams = new XMSSMTParameters(4, 2, digest(0));
        byte[] mtSeed = seedFor(32);

        XMSSMTSigner wrappedMtSigner = new XMSSMTSigner();
        wrappedMtSigner.init(true, new ParametersWithRandom(xmssMtKey(mtParams, mtSeed).getPrivate(), random));
        byte[] mtWrapped = XMSSHarnessTests.sign(wrappedMtSigner, MESSAGE);

        XMSSMTSigner plainMtSigner = new XMSSMTSigner();
        plainMtSigner.init(true, xmssMtKey(mtParams, mtSeed).getPrivate());
        assertTrue("XMSS^MT: ParametersWithRandom changed the signature",
            Arrays.areEqual(mtWrapped, XMSSHarnessTests.sign(plainMtSigner, MESSAGE)));
    }

    private void checkXMSS(String label, XMSSParameters params, byte[] seed)
        throws Exception
    {
        AsymmetricCipherKeyPair kp = xmssKey(params, seed);

        checkEncodings(label, kp);

        XMSSSigner signer = new XMSSSigner();
        signer.init(true, kp.getPrivate());
        byte[] sig = XMSSHarnessTests.sign(signer, MESSAGE);
        assertEquals(label + ": signature", expected(label, "sig"), sha256(sig));

        XMSSSigner verifier = new XMSSSigner();
        verifier.init(false, kp.getPublic());
        assertTrue(label + ": signature did not verify", XMSSHarnessTests.verify(verifier, MESSAGE, sig));
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
        assertTrue(label + ": private key did not round trip", Arrays.areEqual(priv,
            PrivateKeyInfoFactory.createPrivateKeyInfo(PrivateKeyFactory.createKey(priv)).getEncoded()));
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

    private static AsymmetricCipherKeyPair xmssKey(XMSSParameters params, byte[] seed)
    {
        XMSSKeyPairGenerator gen = new XMSSKeyPairGenerator();
        gen.init(new XMSSKeyGenerationParameters(params, fixedRandom(seed)));
        return gen.generateKeyPair();
    }

    private static AsymmetricCipherKeyPair xmssMtKey(XMSSMTParameters params, byte[] seed)
    {
        XMSSMTKeyPairGenerator gen = new XMSSMTKeyPairGenerator();
        gen.init(new XMSSMTKeyGenerationParameters(params, fixedRandom(seed)));
        return gen.generateKeyPair();
    }

    private static Digest digest(int n)
    {
        switch (n)
        {
        case 0:
            return new SHA256Digest();
        case 1:
            return new SHAKEDigest(128);
        case 2:
            return new SHA512Digest();
        default:
            return new SHAKEDigest(256);
        }
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
        // key generation reads three tree-digest-sized blocks (3 * 64 at the largest parameter set)
        byte[] material = new byte[6 * seed.length];
        for (int i = 0; i != 6; i++)
        {
            System.arraycopy(seed, 0, material, i * seed.length, seed.length);
        }

        return new FixedSecureRandom(new FixedSecureRandom.Source[]{ new FixedSecureRandom.Data(material) });
    }
}
