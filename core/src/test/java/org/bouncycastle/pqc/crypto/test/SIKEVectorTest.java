package org.bouncycastle.pqc.crypto.test;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.HashMap;

import junit.framework.TestCase;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.pqc.crypto.sike.SIKEKEMExtractor;
import org.bouncycastle.pqc.crypto.sike.SIKEKEMGenerator;
import org.bouncycastle.pqc.crypto.sike.SIKEKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.sike.SIKEKeyPairGenerator;
import org.bouncycastle.pqc.crypto.sike.SIKEParameters;
import org.bouncycastle.pqc.crypto.sike.SIKEPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.sike.SIKEPublicKeyParameters;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

public class SIKEVectorTest
        extends TestCase
{
    public void testVector()
            throws Exception
    {
        boolean full = System.getProperty("test.full", "false").equals("true");
        full = true; //todo: remove

        String[] files;
        if(full)
        {
            files = new String[]{
                    "PQCkemKAT_374.rsp", //434
                    "PQCkemKAT_434.rsp", //503
                    "PQCkemKAT_524.rsp", //610
                    "PQCkemKAT_644.rsp", //751
                    "PQCkemKAT_350.rsp", //434 compressed
                    "PQCkemKAT_407.rsp", //503 compressed
                    "PQCkemKAT_491.rsp", //610 compressed
                    "PQCkemKAT_602.rsp", //751 compressed
            };
        }
        else
        {
            files = new String[]{
                    "PQCkemKAT_374.rsp",
                    "PQCkemKAT_350.rsp", //compressed
            };
        }

        SIKEParameters[] params = new SIKEParameters[]{
                SIKEParameters.sikep434,
                SIKEParameters.sikep503,
                SIKEParameters.sikep610,
                SIKEParameters.sikep751,
                SIKEParameters.sikep434_compressed,
                SIKEParameters.sikep503_compressed,
                SIKEParameters.sikep610_compressed,
                SIKEParameters.sikep751_compressed,
        };

        for (int fileIndex = 0; fileIndex != files.length; fileIndex++)
        {
            String name = files[fileIndex];
            System.out.println("testing: " + name);
            InputStream src = SIKEVectorTest.class.getResourceAsStream("/org/bouncycastle/pqc/crypto/test/sike/" + name);
            BufferedReader bin = new BufferedReader(new InputStreamReader(src));

            String line = null;
            HashMap<String, String> buf = new HashMap<String, String>();
//            Random rnd = new Random(System.currentTimeMillis());
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
                        if (!"0".equals(count))
                        {
//                            // randomly skip tests after zero.
//                            if (rnd.nextBoolean())
//                            {
//                                continue;
//                            }
                        }
                        System.out.println("test case: " + count);
                        byte[] seed = Hex.decode((String)buf.get("seed")); // seed for sike secure random
                        byte[] pk = Hex.decode((String)buf.get("pk"));     // public key
                        byte[] sk = Hex.decode((String)buf.get("sk"));     // private key
                        byte[] ct = Hex.decode((String)buf.get("ct"));     // ciphertext
                        byte[] ss = Hex.decode((String)buf.get("ss"));     // session key

                        NISTSecureRandom random = new NISTSecureRandom(seed, null);
                        SIKEParameters parameters = params[fileIndex];

                        SIKEKeyPairGenerator kpGen = new SIKEKeyPairGenerator();
                        SIKEKeyGenerationParameters genParam = new SIKEKeyGenerationParameters(random, parameters);
                        //
                        // Generate keys and test.
                        //
                        kpGen.init(genParam);
                        AsymmetricCipherKeyPair kp = kpGen.generateKeyPair();

                        SIKEPublicKeyParameters pubParams = (SIKEPublicKeyParameters) kp.getPublic();
//                                (SIKEPublicKeyParameters)PublicKeyFactory.createKey(SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo((SIKEPublicKeyParameters)kp.getPublic()));
                        SIKEPrivateKeyParameters privParams = (SIKEPrivateKeyParameters) kp.getPrivate();
//                            (SIKEPrivateKeyParameters)PrivateKeyFactory.createKey(PrivateKeyInfoFactory.createPrivateKeyInfo((SIKEPrivateKeyParameters)kp.getPrivate()));

//                        System.out.println(Hex.toHexString(pk).toUpperCase());
//                        System.out.println(Hex.toHexString(pubParams.getPublicKey()).toUpperCase());

//                        System.out.println(Hex.toHexString(sk).toUpperCase());
//                        System.out.println(Hex.toHexString(privParams.getPrivateKey()).toUpperCase());

                        assertTrue(name + " " + count + ": public key", Arrays.areEqual(pk, pubParams.getPublicKey()));
                        assertTrue(name + " " + count + ": secret key", Arrays.areEqual(sk, privParams.getPrivateKey()));

                        // KEM Enc
                        SIKEKEMGenerator sikeEncCipher = new SIKEKEMGenerator(random);
                        SecretWithEncapsulation secWenc = sikeEncCipher.generateEncapsulated(pubParams);
                        byte[] generated_cipher_text = secWenc.getEncapsulation();


//                        System.out.println(Hex.toHexString(ct));
//                        System.out.println(Hex.toHexString(generated_cipher_text));

                        assertTrue(name + " " + count + ": kem_enc cipher text", Arrays.areEqual(ct, generated_cipher_text));
                        byte[] secret = secWenc.getSecret();

//                        System.out.println(Hex.toHexString(ss).toUpperCase());
//                        System.out.println(Hex.toHexString(secret).toUpperCase());
                        assertTrue(name + " " + count + ": kem_enc key", Arrays.areEqual(ss, secret));

                        // KEM Dec
                        SIKEKEMExtractor sikeDecCipher = new SIKEKEMExtractor(privParams);

                        byte[] dec_key = sikeDecCipher.extractSecret(generated_cipher_text);

//                        System.out.println(Hex.toHexString(dec_key).toUpperCase());
//                        System.out.println(Hex.toHexString(ss).toUpperCase());

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
