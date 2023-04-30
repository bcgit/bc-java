package org.bouncycastle.pqc.crypto.test;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.HashMap;

import junit.framework.TestCase;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.pqc.crypto.frodo.FrodoKEMExtractor;
import org.bouncycastle.pqc.crypto.frodo.FrodoKEMGenerator;
import org.bouncycastle.pqc.crypto.frodo.FrodoKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.frodo.FrodoKeyPairGenerator;
import org.bouncycastle.pqc.crypto.frodo.FrodoParameters;
import org.bouncycastle.pqc.crypto.frodo.FrodoPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.frodo.FrodoPublicKeyParameters;
import org.bouncycastle.pqc.crypto.util.PrivateKeyFactory;
import org.bouncycastle.pqc.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.pqc.crypto.util.PublicKeyFactory;
import org.bouncycastle.pqc.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.test.TestResourceFinder;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

public class FrodoVectorTest
    extends TestCase
{
    public void testParameters()
        throws Exception
    {
        assertEquals(128, FrodoParameters.frodokem640aes.getSessionKeySize());
        assertEquals(128, FrodoParameters.frodokem640shake.getSessionKeySize());
        assertEquals(192, FrodoParameters.frodokem976aes.getSessionKeySize());
        assertEquals(192, FrodoParameters.frodokem976shake.getSessionKeySize());
        assertEquals(256, FrodoParameters.frodokem1344aes.getSessionKeySize());
        assertEquals(256, FrodoParameters.frodokem1344shake.getSessionKeySize());
    }

    public void testVectors()
        throws Exception
    {
        String[] files = new String[]{
            "PQCkemKAT_19888.rsp",
            "PQCkemKAT_31296.rsp",
            "PQCkemKAT_43088.rsp",
            "PQCkemKAT_19888_shake.rsp",
            "PQCkemKAT_31296_shake.rsp",
            "PQCkemKAT_43088_shake.rsp"
        };

        FrodoParameters[] params = new FrodoParameters[]{
            FrodoParameters.frodokem640aes,
            FrodoParameters.frodokem976aes,
            FrodoParameters.frodokem1344aes,
            FrodoParameters.frodokem640shake,
            FrodoParameters.frodokem976shake,
            FrodoParameters.frodokem1344shake
        };
        
        TestSampler sampler = new TestSampler();
        for (int fileIndex = 0; fileIndex != files.length; fileIndex++)
        {
            String name = files[fileIndex];
            System.out.println("testing: " + name);
            InputStream src = TestResourceFinder.findTestResource("pqc/crypto/frodo", name);
            BufferedReader bin = new BufferedReader(new InputStreamReader(src));

            String line = null;
            HashMap<String, String> buf = new HashMap<String, String>();
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

                        byte[] seed = Hex.decode((String)buf.get("seed")); // seed for nist secure random
                        byte[] pk = Hex.decode((String)buf.get("pk"));     // public key
                        byte[] sk = Hex.decode((String)buf.get("sk"));     // private key
                        byte[] ct = Hex.decode((String)buf.get("ct"));     // ciphertext
                        byte[] ss = Hex.decode((String)buf.get("ss"));     // session key

                        NISTSecureRandom random = new NISTSecureRandom(seed, null);
                        FrodoParameters parameters = params[fileIndex];

                        FrodoKeyPairGenerator kpGen = new FrodoKeyPairGenerator();
                        FrodoKeyGenerationParameters genParams = new FrodoKeyGenerationParameters(random, parameters);
                        //
                        // Generate keys and test.
                        //
                        kpGen.init(genParams);
                        AsymmetricCipherKeyPair kp = kpGen.generateKeyPair();

                        FrodoPublicKeyParameters pubParams = (FrodoPublicKeyParameters)PublicKeyFactory.createKey(
                            SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo((FrodoPublicKeyParameters)kp.getPublic()));
                        FrodoPrivateKeyParameters privParams = (FrodoPrivateKeyParameters)PrivateKeyFactory.createKey(
                            PrivateKeyInfoFactory.createPrivateKeyInfo((FrodoPrivateKeyParameters)kp.getPrivate()));

                        assertTrue(name + " " + count + ": public key", Arrays.areEqual(pk, pubParams.getPublicKey()));
                        assertTrue(name + " " + count + ": secret key", Arrays.areEqual(sk, privParams.getPrivateKey()));

                        // kem_enc
                        FrodoKEMGenerator frodoEncCipher = new FrodoKEMGenerator(random);
                        SecretWithEncapsulation secWenc = frodoEncCipher.generateEncapsulated(pubParams);
                        byte[] generated_cipher_text = secWenc.getEncapsulation();
                        assertTrue(name + " " + count + ": kem_enc cipher text", Arrays.areEqual(ct, generated_cipher_text));
                        byte[] secret = secWenc.getSecret();
                        assertTrue(name + " " + count + ": kem_enc key", Arrays.areEqual(ss, secret));

                        // kem_dec
                        FrodoKEMExtractor frodoDecCipher = new FrodoKEMExtractor(privParams);

                        byte[] dec_key = frodoDecCipher.extractSecret(generated_cipher_text);

                        assertEquals(parameters.getSessionKeySize(), dec_key.length * 8);
                        assertTrue(name + " " + count + ": kem_dec ss", Arrays.areEqual(dec_key, ss));
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
            System.out.println("testing successful!");
        }
    }
}
