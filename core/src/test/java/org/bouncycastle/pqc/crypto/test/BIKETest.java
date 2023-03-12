package org.bouncycastle.pqc.crypto.test;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.HashMap;
import java.util.Random;

import junit.framework.TestCase;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.pqc.crypto.bike.BIKEKEMExtractor;
import org.bouncycastle.pqc.crypto.bike.BIKEKEMGenerator;
import org.bouncycastle.pqc.crypto.bike.BIKEKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.bike.BIKEKeyPairGenerator;
import org.bouncycastle.pqc.crypto.bike.BIKEParameters;
import org.bouncycastle.pqc.crypto.bike.BIKEPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.bike.BIKEPublicKeyParameters;
import org.bouncycastle.pqc.crypto.util.PrivateKeyFactory;
import org.bouncycastle.pqc.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.pqc.crypto.util.PublicKeyFactory;
import org.bouncycastle.pqc.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.test.TestResourceFinder;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

public class BIKETest
    extends TestCase
{

    @Override
    public String getName()
    {
        return "BIKE Test";
    }

    public void testVectors()
        throws Exception
    {
//        boolean full = System.getProperty("test.full", "false").equals("true");

        String[] files;
        files = new String[]{
            "PQCkemKAT_BIKE_3114.rsp",
            "PQCkemKAT_BIKE_6198.rsp",
            "PQCkemKAT_BIKE_10276.rsp"
        };

        BIKEParameters[] listParams = new BIKEParameters[]{
            BIKEParameters.bike128,
            BIKEParameters.bike192,
            BIKEParameters.bike256
        };

        TestSampler sampler = new TestSampler();
        for (int fileIndex = 0; fileIndex < files.length; fileIndex++)
        {
            String name = files[fileIndex];

            InputStream src = TestResourceFinder.findTestResource("pqc/crypto/bike", name);
            BufferedReader bin = new BufferedReader(new InputStreamReader(src));

            String line = null;
            HashMap<String, String> buf = new HashMap<String, String>();
            Random rnd = new Random(System.currentTimeMillis());

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

                        System.out.println("test case: " + count);
                        byte[] seed = Hex.decode((String)buf.get("seed")); // seed for bike secure random
                        byte[] pk = Hex.decode((String)buf.get("pk"));     // public key
                        byte[] sk = Hex.decode((String)buf.get("sk"));     // private key
                        byte[] ct = Hex.decode((String)buf.get("ct"));     // ciphertext
                        byte[] ss = Hex.decode((String)buf.get("ss"));     // session key

                        NISTSecureRandom random = new NISTSecureRandom(seed, null);
                        BIKEParameters parameters = listParams[fileIndex];

                        BIKEKeyPairGenerator bikeKeyGen = new BIKEKeyPairGenerator();
                        BIKEKeyGenerationParameters genParam = new BIKEKeyGenerationParameters(random, parameters);

                        //
                        // Generate keys and test.
                        //

                        // KEM Keypair
                        bikeKeyGen.init(genParam);
                        AsymmetricCipherKeyPair pair = bikeKeyGen.generateKeyPair();

                        BIKEPublicKeyParameters generatedPk = (BIKEPublicKeyParameters)PublicKeyFactory.createKey(SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo((BIKEPublicKeyParameters)pair.getPublic()));
                        BIKEPrivateKeyParameters generatedSk = (BIKEPrivateKeyParameters)PrivateKeyFactory.createKey(PrivateKeyInfoFactory.createPrivateKeyInfo((BIKEPrivateKeyParameters)pair.getPrivate()));
                        assertTrue(name + " " + count + ": public key", Arrays.areEqual(pk, generatedPk.getEncoded()));
                        assertTrue(name + " " + count + ": secret key", Arrays.areEqual(sk, generatedSk.getEncoded()));

                        // KEM Encapsulation
                        BIKEKEMGenerator bikekemGenerator = new BIKEKEMGenerator(random);
                        SecretWithEncapsulation secretWithEnc = bikekemGenerator.generateEncapsulated(generatedPk);
                        byte[] secret = secretWithEnc.getSecret();
                        byte[] c = secretWithEnc.getEncapsulation();

                        assertTrue(name + " " + count + ": ciphertext", Arrays.areEqual(c, ct));
                        assertTrue(name + " " + count + ": kem_dec ss", Arrays.areEqual(secret, 0, secret.length, ss, 0, secret.length));

                        // KEM Decapsulation
                        BIKEKEMExtractor bikekemExtractor = new BIKEKEMExtractor(generatedSk);
                        byte[] dec_key = bikekemExtractor.extractSecret(c);

                        assertEquals(parameters.getSessionKeySize(), secret.length * 8);
                        assertTrue(name + " " + count + ": kem_dec ss", Arrays.areEqual(dec_key, 0, dec_key.length, ss, 0, dec_key.length));
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
            System.out.println("Testing successful!");
        }
    }
}
