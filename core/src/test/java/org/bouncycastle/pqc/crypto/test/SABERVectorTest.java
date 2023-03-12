package org.bouncycastle.pqc.crypto.test;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.HashMap;

import junit.framework.TestCase;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.pqc.crypto.saber.SABERKEMExtractor;
import org.bouncycastle.pqc.crypto.saber.SABERKEMGenerator;
import org.bouncycastle.pqc.crypto.saber.SABERKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.saber.SABERKeyPairGenerator;
import org.bouncycastle.pqc.crypto.saber.SABERParameters;
import org.bouncycastle.pqc.crypto.saber.SABERPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.saber.SABERPublicKeyParameters;
import org.bouncycastle.pqc.crypto.util.PrivateKeyFactory;
import org.bouncycastle.pqc.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.pqc.crypto.util.PublicKeyFactory;
import org.bouncycastle.pqc.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.test.TestResourceFinder;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

public class SABERVectorTest
    extends TestCase
{
    public void testParameters()
        throws Exception
    {
        assertEquals(128, SABERParameters.lightsaberkem128r3.getSessionKeySize());
        assertEquals(128, SABERParameters.saberkem128r3.getSessionKeySize());
        assertEquals(128, SABERParameters.firesaberkem128r3.getSessionKeySize());
        assertEquals(192, SABERParameters.lightsaberkem192r3.getSessionKeySize());
        assertEquals(192, SABERParameters.saberkem192r3.getSessionKeySize());
        assertEquals(192, SABERParameters.firesaberkem192r3.getSessionKeySize());
        assertEquals(256, SABERParameters.lightsaberkem256r3.getSessionKeySize());
        assertEquals(256, SABERParameters.saberkem256r3.getSessionKeySize());
        assertEquals(256, SABERParameters.firesaberkem256r3.getSessionKeySize());
    }

    public void testVectors()
        throws Exception
    {

        SABERParameters[] params = new SABERParameters[] {
                SABERParameters.lightsaberkem256r3,
                SABERParameters.saberkem256r3,
                SABERParameters.firesaberkem256r3,

                SABERParameters.ulightsaberkemr3,
                SABERParameters.usaberkemr3,
                SABERParameters.ufiresaberkemr3,

                SABERParameters.lightsaberkem90sr3,
                SABERParameters.saberkem90sr3,
                SABERParameters.firesaberkem90sr3,

                SABERParameters.ulightsaberkem90sr3,
                SABERParameters.usaberkem90sr3,
                SABERParameters.ufiresaberkem90sr3,
        };
        String[] files = new String[] {
                "lightsaber.rsp",
                "saber.rsp",
                "firesaber.rsp",

                "ulightsaber.rsp",
                "usaber.rsp",
                "ufiresaber.rsp",

                "lightsaber-90s.rsp",
                "saber-90s.rsp",
                "firesaber-90s.rsp",

                "ulightsaber-90s.rsp",
                "usaber-90s.rsp",
                "ufiresaber-90s.rsp",
        };

        TestSampler sampler = new TestSampler();

        for (int fileIndex = 0; fileIndex != files.length; fileIndex++)
        {
            String name = files[fileIndex];
            System.out.println("testing: " + name);
            InputStream src = TestResourceFinder.findTestResource("pqc/crypto/saber", name);
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

                        byte[] seed = Hex.decode((String)buf.get("seed")); // seed for SABER secure random
                        byte[] pk = Hex.decode((String)buf.get("pk"));     // public key
                        byte[] sk = Hex.decode((String)buf.get("sk"));     // private key
                        byte[] ct = Hex.decode((String)buf.get("ct"));     // ciphertext
                        byte[] ss = Hex.decode((String)buf.get("ss"));     // session key

                        NISTSecureRandom random = new NISTSecureRandom(seed, null);
                        SABERParameters parameters = params[fileIndex];

                        SABERKeyPairGenerator kpGen = new SABERKeyPairGenerator();
                        SABERKeyGenerationParameters genParam = new SABERKeyGenerationParameters(random, parameters);
                        //
                        // Generate keys and test.
                        //
                        kpGen.init(genParam);
                        AsymmetricCipherKeyPair kp = kpGen.generateKeyPair();

                        SABERPublicKeyParameters pubParams = (SABERPublicKeyParameters) PublicKeyFactory.createKey(SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo((SABERPublicKeyParameters)kp.getPublic()));
                        SABERPrivateKeyParameters privParams = (SABERPrivateKeyParameters) PrivateKeyFactory.createKey(PrivateKeyInfoFactory.createPrivateKeyInfo((SABERPrivateKeyParameters)kp.getPrivate()));


                        assertTrue(name + " " + count + ": public key", Arrays.areEqual(pk, pubParams.getPublicKey()));
                        assertTrue(name + " " + count + ": secret key", Arrays.areEqual(sk, privParams.getPrivateKey()));

                        // KEM Enc
                        SABERKEMGenerator SABEREncCipher = new SABERKEMGenerator(random);
                        SecretWithEncapsulation secWenc = SABEREncCipher.generateEncapsulated(pubParams);
                        byte[] generated_cipher_text = secWenc.getEncapsulation();
                        assertTrue(name + " " + count + ": kem_enc cipher text", Arrays.areEqual(ct, generated_cipher_text));
                        byte[] secret = secWenc.getSecret();
                        assertTrue(name + " " + count + ": kem_enc key", Arrays.areEqual(ss, secret));

                        // KEM Dec
                        SABERKEMExtractor SABERDecCipher = new SABERKEMExtractor(privParams);

                        byte[] dec_key = SABERDecCipher.extractSecret(generated_cipher_text);

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
