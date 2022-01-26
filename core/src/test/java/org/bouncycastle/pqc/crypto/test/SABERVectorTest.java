package org.bouncycastle.pqc.crypto.test;

import junit.framework.TestCase;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.pqc.crypto.saber.*;
import org.bouncycastle.pqc.crypto.util.PrivateKeyFactory;
import org.bouncycastle.pqc.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.pqc.crypto.util.PublicKeyFactory;
import org.bouncycastle.pqc.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.HashMap;

public class SABERVectorTest
    extends TestCase
{
    public void testParamaters()
        throws Exception
    {
        SABERParameters[] params = new SABERParameters[] {
                SABERParameters.lightsaberkemr3,
                SABERParameters.saberkemr3,
                SABERParameters.firesaberkemr3
            };

        assertEquals(32, SABERParameters.lightsaberkemr3.getDefaultKeySize());
        assertEquals(32, SABERParameters.saberkemr3.getDefaultKeySize());
        assertEquals(32, SABERParameters.firesaberkemr3.getDefaultKeySize());
    }

    public void testVectors()
        throws Exception
    {

        SABERParameters[] params = new SABERParameters[] {
            SABERParameters.lightsaberkemr3,
            SABERParameters.saberkemr3,
            SABERParameters.firesaberkemr3
        };
        String[] files = new String[] {
                "lightsaber.rsp",
                "saber.rsp",
                "firesaber.rsp"
        };

        for (int fileIndex = 0; fileIndex != files.length; fileIndex++)
        {
            String name = files[fileIndex];
            System.out.println("testing: " + name);
            InputStream src = SABERVectorTest.class.getResourceAsStream("/org/bouncycastle/pqc/crypto/test/saber/" + name);
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
                        String count = buf.get("count");
                        System.out.println("test case: " + count);

                        byte[] seed = Hex.decode(buf.get("seed")); // seed for SABER secure random
                        byte[] pk = Hex.decode(buf.get("pk"));     // public key
                        byte[] sk = Hex.decode(buf.get("sk"));     // private key
                        byte[] ct = Hex.decode(buf.get("ct"));     // ciphertext
                        byte[] ss = Hex.decode(buf.get("ss"));     // session key

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
