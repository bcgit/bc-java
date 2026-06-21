package org.bouncycastle.pqc.crypto.test;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.HashMap;

import junit.framework.TestCase;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.crypto.generators.FrodoKEMKeyPairGenerator;
import org.bouncycastle.crypto.kems.FrodoKEMExtractor;
import org.bouncycastle.crypto.kems.FrodoKEMGenerator;
import org.bouncycastle.crypto.params.FrodoKEMKeyGenerationParameters;
import org.bouncycastle.crypto.params.FrodoKEMParameters;
import org.bouncycastle.crypto.params.FrodoKEMPrivateKeyParameters;
import org.bouncycastle.crypto.params.FrodoKEMPublicKeyParameters;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.test.TestResourceFinder;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

/**
 * KAT tests for the standardised FrodoKEM (ISO/IEC 18033-2) under org.bouncycastle.crypto: the
 * salted "FrodoKEM" and ephemeral "eFrodoKEM" parameter sets, in both SHAKE and AES gen-matrix
 * variants, at security levels 976 and 1344. Vectors are the FrodoKEM team's reference KATs (salted
 * from the FrodoKEM tree, ephemeral from the eFrodoKEM tree).
 */
public class FrodoKEMVectorTest
    extends TestCase
{
    public void testParameters()
        throws Exception
    {
        assertEquals(192, FrodoKEMParameters.frodokem976shake.getSessionKeySize());
        assertEquals(256, FrodoKEMParameters.frodokem1344shake.getSessionKeySize());
        assertEquals(192, FrodoKEMParameters.efrodokem976shake.getSessionKeySize());
        assertEquals(256, FrodoKEMParameters.efrodokem1344shake.getSessionKeySize());
        assertEquals(192, FrodoKEMParameters.frodokem976aes.getSessionKeySize());
        assertEquals(256, FrodoKEMParameters.frodokem1344aes.getSessionKeySize());
        assertEquals(192, FrodoKEMParameters.efrodokem976aes.getSessionKeySize());
        assertEquals(256, FrodoKEMParameters.efrodokem1344aes.getSessionKeySize());
    }

    public void testVectors()
        throws Exception
    {
        String[] files = new String[]{
            "frodokem976shake.rsp",
            "frodokem1344shake.rsp",
            "efrodokem976shake.rsp",
            "efrodokem1344shake.rsp",
            "frodokem976aes.rsp",
            "frodokem1344aes.rsp",
            "efrodokem976aes.rsp",
            "efrodokem1344aes.rsp"
        };

        FrodoKEMParameters[] params = new FrodoKEMParameters[]{
            FrodoKEMParameters.frodokem976shake,
            FrodoKEMParameters.frodokem1344shake,
            FrodoKEMParameters.efrodokem976shake,
            FrodoKEMParameters.efrodokem1344shake,
            FrodoKEMParameters.frodokem976aes,
            FrodoKEMParameters.frodokem1344aes,
            FrodoKEMParameters.efrodokem976aes,
            FrodoKEMParameters.efrodokem1344aes
        };

        for (int fileIndex = 0; fileIndex != files.length; fileIndex++)
        {
            String name = files[fileIndex];

            InputStream src = TestResourceFinder.findTestResource("pqc/crypto/frodo", name);
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

                        byte[] seed = Hex.decode((String)buf.get("seed")); // seed for nist secure random
                        byte[] pk = Hex.decode((String)buf.get("pk"));     // public key
                        byte[] sk = Hex.decode((String)buf.get("sk"));     // private key
                        byte[] ct = Hex.decode((String)buf.get("ct"));     // ciphertext
                        byte[] ss = Hex.decode((String)buf.get("ss"));     // session key

                        NISTSecureRandom random = new NISTSecureRandom(seed, null);
                        FrodoKEMParameters parameters = params[fileIndex];

                        FrodoKEMKeyPairGenerator kpGen = new FrodoKEMKeyPairGenerator();
                        FrodoKEMKeyGenerationParameters genParams = new FrodoKEMKeyGenerationParameters(random, parameters);
                        //
                        // Generate keys and test.
                        //
                        kpGen.init(genParams);
                        AsymmetricCipherKeyPair kp = kpGen.generateKeyPair();

                        FrodoKEMPublicKeyParameters pubParams = (FrodoKEMPublicKeyParameters)PublicKeyFactory.createKey(
                            SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo((FrodoKEMPublicKeyParameters)kp.getPublic()));
                        FrodoKEMPrivateKeyParameters privParams = (FrodoKEMPrivateKeyParameters)PrivateKeyFactory.createKey(
                            PrivateKeyInfoFactory.createPrivateKeyInfo((FrodoKEMPrivateKeyParameters)kp.getPrivate()));

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
        }
    }
}
