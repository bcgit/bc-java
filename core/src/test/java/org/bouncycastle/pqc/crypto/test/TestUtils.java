package org.bouncycastle.pqc.crypto.test;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.SecureRandom;
import java.util.HashMap;

import junit.framework.Assert;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.EncapsulatedSecretExtractor;
import org.bouncycastle.crypto.EncapsulatedSecretGenerator;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.pqc.crypto.MessageSigner;
import org.bouncycastle.pqc.crypto.util.PrivateKeyFactory;
import org.bouncycastle.pqc.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.pqc.crypto.util.PublicKeyFactory;
import org.bouncycastle.pqc.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.test.TestResourceFinder;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

class TestUtils
{
    static boolean parseBoolean(String value)
    {
        return "true".equalsIgnoreCase(value);
    }

    public interface SignerOperation
    {
        SecureRandom getSecureRandom(byte[] seed);

        AsymmetricCipherKeyPairGenerator getAsymmetricCipherKeyPairGenerator(int fileIndex, SecureRandom random);

        byte[] getPublicKeyEncoded(AsymmetricKeyParameter pubParams);

        byte[] getPrivateKeyEncoded(CipherParameters privParams);

        Signer getSigner();

        MessageSigner getMessageSigner();
    }

    public interface KeyEncapsulationOperation
    {
        SecureRandom getSecureRandom(byte[] seed);

        AsymmetricCipherKeyPairGenerator getAsymmetricCipherKeyPairGenerator(int fileIndex, SecureRandom random);

        byte[] getPublicKeyEncoded(AsymmetricKeyParameter pubParams);

        byte[] getPrivateKeyEncoded(AsymmetricKeyParameter privParams);

        EncapsulatedSecretGenerator getKEMGenerator(SecureRandom random);

        EncapsulatedSecretExtractor getKEMExtractor(AsymmetricKeyParameter privParams);

        int getSessionKeySize();
    }

    public static void testTestVector(boolean sampleOnly, boolean enableFactory, boolean isSigner, String homeDir, String[] files, SignerOperation operation)
        throws Exception
    {
        for (int fileIndex = 0; fileIndex != files.length; fileIndex++)
        {
            String name = files[fileIndex];

            InputStream src = TestResourceFinder.findTestResource(homeDir, name);
            BufferedReader bin = new BufferedReader(new InputStreamReader(src));

            String line;
            HashMap<String, String> buf = new HashMap<String, String>();
            TestSampler sampler = sampleOnly ? new TestSampler() : null;
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
                        if (sampler != null && sampler.skipTest(count))
                        {
                            continue;
                        }

                        byte[] seed = Hex.decode((String)buf.get("seed"));
                        byte[] pk = Hex.decode((String)buf.get("pk"));
                        byte[] sk = Hex.decode((String)buf.get("sk"));
                        byte[] message = Hex.decode((String)buf.get("msg"));
                        byte[] signature = Hex.decode((String)buf.get("sm"));

                        SecureRandom random = operation.getSecureRandom(seed);

                        AsymmetricCipherKeyPairGenerator kpGen = operation.getAsymmetricCipherKeyPairGenerator(fileIndex, random);

                        //
                        // Generate keys and test.
                        //
                        AsymmetricCipherKeyPair kp = kpGen.generateKeyPair();
                        AsymmetricKeyParameter pubParams;
                        CipherParameters privParams;
                        if (enableFactory)
                        {
                            pubParams = PublicKeyFactory.createKey(
                                SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(kp.getPublic()));
                            privParams = PrivateKeyFactory.createKey(
                                PrivateKeyInfoFactory.createPrivateKeyInfo(kp.getPrivate()));
                        }
                        else
                        {
                            pubParams = kp.getPublic();
                            privParams = kp.getPrivate();
                        }

                        Assert.assertTrue(name + ": public key", Arrays.areEqual(pk, operation.getPublicKeyEncoded(pubParams)));
                        Assert.assertTrue(name + ": secret key", Arrays.areEqual(sk, operation.getPrivateKeyEncoded(privParams)));

                        byte[] sigGenerated;
                        privParams = new ParametersWithRandom(privParams, random);
                        if (isSigner)
                        {
                            Signer signer = operation.getSigner();
                            signer.init(true, privParams);
                            signer.update(message, 0, message.length);
                            sigGenerated = signer.generateSignature();
                        }
                        else
                        {
                            MessageSigner signer = operation.getMessageSigner();
                            signer.init(true, privParams);
                            sigGenerated = signer.generateSignature(message);
                        }

                        Assert.assertTrue(Arrays.areEqual(sigGenerated, signature));

                        if (isSigner)
                        {
                            Signer signer = operation.getSigner();
                            signer.init(false, pubParams);
                            signer.update(message, 0, message.length);
                            Assert.assertTrue(signer.verifySignature(sigGenerated));
                        }
                        else
                        {
                            MessageSigner signer = operation.getMessageSigner();
                            signer.init(false, pubParams);
                            Assert.assertTrue(signer.verifySignature(message, sigGenerated));
                        }
                        System.out.println("Count " + count + " pass");
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

    public static void testTestVector(boolean sampleOnly, boolean enableFactory, String homeDir, String[] files, KeyEncapsulationOperation operation)
        throws Exception
    {
        for (int fileIndex = 0; fileIndex < files.length; fileIndex++)
        {
            String name = files[fileIndex];
            //System.out.println(files[fileIndex]);
            InputStream src = TestResourceFinder.findTestResource(homeDir, name);
            BufferedReader bin = new BufferedReader(new InputStreamReader(src));

            String line = null;
            HashMap<String, String> buf = new HashMap<String, String>();
            TestSampler sampler = sampleOnly ? new TestSampler() : null;
            while ((line = bin.readLine()) != null)
            {
                line = line.trim();

                if (line.startsWith("#"))
                {
                    continue;
                }
                if (line.isEmpty())
                {
                    if (!buf.isEmpty())
                    {
                        String count = (String)buf.get("count");
                        if (sampler != null && sampler.skipTest(count))
                        {
                            continue;
                        }
                         System.out.println("test case: " + count);

                        byte[] seed = Hex.decode((String)buf.get("seed")); // seed for bike secure random
                        byte[] pk = Hex.decode((String)buf.get("pk"));     // public key
                        byte[] sk = Hex.decode((String)buf.get("sk"));     // private key
                        byte[] ct = Hex.decode((String)buf.get("ct"));     // ciphertext
                        byte[] ss = Hex.decode((String)buf.get("ss"));     // session key

                        SecureRandom random = operation.getSecureRandom(seed);

                        AsymmetricCipherKeyPairGenerator kpGen = operation.getAsymmetricCipherKeyPairGenerator(fileIndex, random);

                        //
                        // Generate keys and test.
                        //
                        AsymmetricCipherKeyPair kp = kpGen.generateKeyPair();
                        AsymmetricKeyParameter pubParams;
                        AsymmetricKeyParameter privParams;
                        if (enableFactory)
                        {
                            pubParams = PublicKeyFactory.createKey(
                                SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(kp.getPublic()));
                            privParams = PrivateKeyFactory.createKey(
                                PrivateKeyInfoFactory.createPrivateKeyInfo(kp.getPrivate()));
                        }
                        else
                        {
                            pubParams = kp.getPublic();
                            privParams = kp.getPrivate();
                        }

                        Assert.assertTrue(name + " " + count + ": public key", Arrays.areEqual(pk, operation.getPublicKeyEncoded(pubParams)));
                        Assert.assertTrue(name + " " + count + ": secret key", Arrays.areEqual(sk, operation.getPrivateKeyEncoded(privParams)));

                        // KEM Encapsulation
                        EncapsulatedSecretGenerator kemGenerator = operation.getKEMGenerator(random);
                        SecretWithEncapsulation secretWithEnc = kemGenerator.generateEncapsulated(pubParams);
                        byte[] secret = secretWithEnc.getSecret();
                        byte[] c = secretWithEnc.getEncapsulation();

                        Assert.assertTrue(name + " " + count + ": ciphertext", Arrays.areEqual(c, ct));
                        Assert.assertTrue(name + " " + count + ": kem_dec ss", Arrays.areEqual(secret, 0, secret.length, ss, 0, secret.length));

                        // KEM Decapsulation
                        EncapsulatedSecretExtractor kemExtractor = operation.getKEMExtractor(privParams);
                        byte[] dec_key = kemExtractor.extractSecret(c);

                        //Assert.assertTrue(operation.getSessionKeySize() == secret.length * 8);
                        Assert.assertTrue(name + " " + count + ": kem_dec key", Arrays.areEqual(dec_key, secret));
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
}
