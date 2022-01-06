package org.bouncycastle.pqc.crypto.test;

import junit.framework.TestCase;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.pqc.crypto.frodo.*;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.HashMap;

public class FrodoVectorTest
    extends TestCase
{
    public void testParameters()
        throws Exception
    {
        FrodoParameters[] params = new FrodoParameters[]{
                FrodoParameters.frodokem19888r3,
                FrodoParameters.frodokem19888shaker3,
                FrodoParameters.frodokem31296r3,
                FrodoParameters.frodokem31296shaker3,
                FrodoParameters.frodokem43088r3,
                FrodoParameters.frodokem43088shaker3
        };

        assertEquals(64, FrodoParameters.frodokem19888r3.getDefaultKeySize());
        assertEquals(64, FrodoParameters.frodokem19888shaker3.getDefaultKeySize());
        assertEquals(96, FrodoParameters.frodokem31296r3.getDefaultKeySize());
        assertEquals(96, FrodoParameters.frodokem31296shaker3.getDefaultKeySize());
        assertEquals(128, FrodoParameters.frodokem43088r3.getDefaultKeySize());
        assertEquals(128, FrodoParameters.frodokem43088shaker3.getDefaultKeySize());
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
            FrodoParameters.frodokem19888r3,
            FrodoParameters.frodokem31296r3,
            FrodoParameters.frodokem43088r3,
            FrodoParameters.frodokem19888shaker3,
            FrodoParameters.frodokem31296shaker3,
            FrodoParameters.frodokem43088shaker3
        };
        for (int fileIndex = 0; fileIndex != files.length; fileIndex++)
        {
            String name = files[fileIndex];
            System.out.println("testing: " + name);
            InputStream src = SphincsPlusTest.class.getResourceAsStream("/org/bouncycastle/pqc/crypto/test/frodo/" + name);
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

                        byte[] seed = Hex.decode(buf.get("seed")); // seed for nist secure random
                        byte[] pk = Hex.decode(buf.get("pk"));     // public key
                        byte[] sk = Hex.decode(buf.get("sk"));     // private key
                        byte[] ct = Hex.decode(buf.get("ct"));     // ciphertext
                        byte[] ss = Hex.decode(buf.get("ss"));     // session key

                        NISTSecureRandom random = new NISTSecureRandom(seed, null);
                        FrodoParameters parameters = params[fileIndex];

                        FrodoKeyPairGenerator kpGen = new FrodoKeyPairGenerator();
                        FrodoKeyGenerationParameters genParams = new FrodoKeyGenerationParameters(random, parameters);
                        //
                        // Generate keys and test.
                        //
                        kpGen.init(genParams);
                        AsymmetricCipherKeyPair kp = kpGen.generateKeyPair();

                        FrodoPublicKeyParameters pubParams = (FrodoPublicKeyParameters) kp.getPublic();
                        FrodoPrivateKeyParameters privParams = (FrodoPrivateKeyParameters) kp.getPrivate();

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
