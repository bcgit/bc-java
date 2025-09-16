package org.bouncycastle.pqc.crypto.test;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.SecureRandom;
import java.util.HashMap;

import junit.framework.TestCase;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.pqc.crypto.hqc.HQCKEMExtractor;
import org.bouncycastle.pqc.crypto.hqc.HQCKEMGenerator;
import org.bouncycastle.pqc.crypto.hqc.HQCKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.hqc.HQCKeyPairGenerator;
import org.bouncycastle.pqc.crypto.hqc.HQCParameters;
import org.bouncycastle.pqc.crypto.hqc.HQCPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.hqc.HQCPublicKeyParameters;
import org.bouncycastle.pqc.crypto.util.PrivateKeyFactory;
import org.bouncycastle.pqc.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.pqc.crypto.util.PublicKeyFactory;
import org.bouncycastle.pqc.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.test.TestResourceFinder;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.FixedSecureRandom;

public class HQCTest
    extends TestCase
{
    public static void main(String[] args)
        throws Exception
    {
        HQCTest test = new HQCTest();
        test.testVectors();
    }

//    static final String[] files = new String[]{
//        "PQCkemKAT_2321.rsp",
//        "PQCkemKAT_4602.rsp",
//        "PQCkemKAT_7333.rsp",
//    };
//
//    HQCParameters[] PARAMETER_SETS = new HQCParameters[]{
//        HQCParameters.hqc128,
//        HQCParameters.hqc192,
//        HQCParameters.hqc256
//    };

    @Override
    public String getName()
    {
        return "HQC Test";
    }

    public void testVectors()
        throws Exception
    {
        boolean full = System.getProperty("test.full", "false").equals("true");

        String[] files;
        // test cases
        files = new String[]{
            "PQCkemKAT_2321.rsp",
            "PQCkemKAT_4602.rsp",
            "PQCkemKAT_7333.rsp",
        };

        HQCParameters[] listParams = new HQCParameters[]{
            HQCParameters.hqc128,
            HQCParameters.hqc192,
            HQCParameters.hqc256
        };

        for (int fileIndex = 0; fileIndex < files.length; fileIndex++)
        {
            String name = files[fileIndex];
            //System.out.println(files[fileIndex]);
            InputStream src = TestResourceFinder.findTestResource("pqc/crypto/hqc", name);
            BufferedReader bin = new BufferedReader(new InputStreamReader(src));

            String line = null;
            HashMap<String, String> buf = new HashMap<String, String>();
            TestSampler sampler = new TestSampler();
            while ((line = bin.readLine()) != null)
            {
                line = line.trim();

                if (line.startsWith("#"))
                {
                    continue;
                }
                if (line.length() == 0)
                {
                    if (buf.size() > 0)
                    {
                        String count = (String)buf.get("count");
                        if (sampler.skipTest(count))
                        {
                            continue;
                        }
                        // System.out.println("test case: " + count);

                        byte[] seed = Hex.decode((String)buf.get("seed")); // seed for bike secure random
                        byte[] pk = Hex.decode((String)buf.get("pk"));     // public key
                        byte[] sk = Hex.decode((String)buf.get("sk"));     // private key
                        byte[] ct = Hex.decode((String)buf.get("ct"));     // ciphertext
                        byte[] ss = Hex.decode((String)buf.get("ss"));     // session key

                        HQCParameters parameters = listParams[fileIndex];
                        SecureRandom random = new Shake256SecureRandom(seed);
                        HQCKeyPairGenerator hqcKeyGen = new HQCKeyPairGenerator();
                        HQCKeyGenerationParameters genParam = new HQCKeyGenerationParameters(random, parameters);

                        //
                        // Generate keys and test.
                        //

                        // KEM Keypair
                        hqcKeyGen.init(genParam);
                        AsymmetricCipherKeyPair pair = hqcKeyGen.generateKeyPair();

                        HQCPublicKeyParameters generatedPk = (HQCPublicKeyParameters)PublicKeyFactory.createKey(SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo((HQCPublicKeyParameters)pair.getPublic()));
                        HQCPrivateKeyParameters generatedSk = (HQCPrivateKeyParameters)PrivateKeyFactory.createKey(PrivateKeyInfoFactory.createPrivateKeyInfo((HQCPrivateKeyParameters)pair.getPrivate()));

                        assertTrue(name + " " + count + ": public key", Arrays.areEqual(pk, generatedPk.getPublicKey()));
                        assertTrue(name + " " + count + ": secret key", Arrays.areEqual(sk, generatedSk.getPrivateKey()));

                        // KEM Encapsulation
                        HQCKEMGenerator hqcKemGenerator = new HQCKEMGenerator(random);
                        SecretWithEncapsulation secretWithEnc = hqcKemGenerator.generateEncapsulated(generatedPk);
                        byte[] secret = secretWithEnc.getSecret();
                        byte[] c = secretWithEnc.getEncapsulation();

                        assertTrue(name + " " + count + ": ciphertext", Arrays.areEqual(c, ct));
                        assertTrue(name + " " + count + ": kem_dec ss", Arrays.areEqual(secret, 0, secret.length, ss, 0, secret.length));

                        // KEM Decapsulation
                        HQCKEMExtractor bikekemExtractor = new HQCKEMExtractor(generatedSk);
                        byte[] dec_key = bikekemExtractor.extractSecret(c);

                        assertEquals(parameters.getSessionKeySize(), secret.length * 8);
                        assertTrue(name + " " + count + ": kem_dec key", Arrays.areEqual(dec_key, secret));
                    }
                    buf.clear();
                    continue;
                }
                int a = line.indexOf("=");
                if (a > -1)
                {
                    buf.put(line.substring(0, a).trim(), line.substring(a + 1).trim());
                }
            }
            // System.out.println("Testing successful!");
        }
    }

    private static class Shake256SecureRandom
        extends SecureRandom
    {
        private final SHAKEDigest digest = new SHAKEDigest(256);

        public Shake256SecureRandom(byte[] seed)
        {
            digest.update(seed, 0, seed.length);
            digest.update((byte) 0);
        }

        public void nextBytes(byte[] bytes)
        {
            digest.doOutput(bytes, 0, bytes.length);
        }
    }
}
