package org.bouncycastle.pqc.crypto.test;

import junit.framework.TestCase;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.pqc.crypto.frodo.*;
import org.bouncycastle.pqc.math.linearalgebra.ByteUtils;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.FixedSecureRandom;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.util.HashMap;

public class FrodoVectorTest
    extends TestCase
{
    public static void main(String[] args) throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, IllegalBlockSizeException, BadPaddingException, IOException, InvalidKeyException
    {
        String files = "PQCkemKAT_19888.rsp PQCkemKAT_31296.rsp PQCkemKAT_43088.rsp PQCkemKAT_19888_shake.rsp PQCkemKAT_31296_shake.rsp PQCkemKAT_43088_shake.rsp";
        for (String name : files.split(" "))
        {
            System.out.println("testing: " + name);
            InputStream src = SphincsPlusTest.class.getResourceAsStream("/org/bouncycastle/pqc/crypto/test/frodo/" + name);
            BufferedReader bin = new BufferedReader(new InputStreamReader(src));

            String line = null;
            HashMap<String, String> buf = new HashMap<String, String>();

            int n = -1;
            String mode = "";

            while ((line = bin.readLine()) != null)
            {
                line = line.trim();

                if (line.startsWith("#"))
                {
                    String[] nameParts = line.split("-");
                    n = Integer.parseInt(nameParts[1]);
                    mode = nameParts[2];
                    continue;
                }
                if (line.length() == 0)
                {
                    if (buf.size() > 0)
                    {
                        String count = buf.get("count");
                        System.out.println("test case: " + count);

                        byte[] seed = Hex.decode(buf.get("seed")); // seed for cmce secure random
                        byte[] pk = Hex.decode(buf.get("pk"));     // public key
                        byte[] sk = Hex.decode(buf.get("sk"));     // private key
                        byte[] ct = Hex.decode(buf.get("ct"));     // ciphertext
                        byte[] ss = Hex.decode(buf.get("ss"));     // session key

                        String[] nameParts = name.split("-");
                        // TESTS HERE
                        System.out.println("Testing: Frodo" + n + mode + ".");
                        NISTSecureRandom random = new NISTSecureRandom(seed, null);
                        FrodoParameters parameters = new FrodoParameters(n, mode.equals("AES"));

                        FrodoKeyPairGenerator kpGen = new FrodoKeyPairGenerator();
                        FrodoKeyGenerationParameters genParams = new FrodoKeyGenerationParameters(random, parameters);
                        kpGen.init(genParams);
                        AsymmetricCipherKeyPair kp = kpGen.generateKeyPair();

                        FrodoPublicKeyParameters pubParams = (FrodoPublicKeyParameters) kp.getPublic();
                        FrodoPrivateKeyParameters privParams = (FrodoPrivateKeyParameters) kp.getPrivate();

                        assertTrue(name + " " + count + ": public key", Arrays.areEqual(pk, pubParams.getPublicKey()));
                        assertTrue(name + " " + count + ": secret key", Arrays.areEqual(sk, privParams.getPrivateKey()));

                        // assert pub and priv keys
                        System.out.println("pk: " + ByteUtils.toHexString(pubParams.getPublicKey()));
                        System.out.println("sk: " + ByteUtils.toHexString(privParams.getPrivateKey()));

                        // kem_enc

                        FrodoKEMGenerator frodoEncCipher = new FrodoKEMGenerator(random);
                        SecretWithEncapsulation secWenc = frodoEncCipher.generateEncapsulated(pubParams);
                        byte[] generated_cipher_text = secWenc.getEncapsulation();

                        assertTrue(name + " " + count + ": kem_enc cipher text", Arrays.areEqual(ct, generated_cipher_text));
                        assertTrue(name + " " + count + ": kem_enc key", Arrays.areEqual(ss, secWenc.getSecret()));

                        // assert ct and ss

                        // kem_dec
                        FrodoKEMExtractor frodoDecCipher = new FrodoKEMExtractor(privParams);

                        byte[] dec_key = frodoDecCipher.extractSecret(generated_cipher_text);

                        assertTrue(name + " " + count + ": kem_dec ss", Arrays.areEqual(dec_key, ss));
                        assertTrue(name + " " + count + ": kem_dec key", Arrays.areEqual(dec_key, secWenc.getSecret()));

                        // assert dec ss


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
        // init

        // keygen
        // Frodo640SHAKE





    }
}
