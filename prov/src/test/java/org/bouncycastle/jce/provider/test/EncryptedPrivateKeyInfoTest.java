package org.bouncycastle.jce.provider.test;

import java.security.AlgorithmParameters;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.PKCS8EncodedKeySpec;

import javax.crypto.Cipher;
import javax.crypto.EncryptedPrivateKeyInfo;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;

import org.bouncycastle.jcajce.PKCS12KeyWithParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.test.SimpleTest;
import org.bouncycastle.util.test.Test;
import org.bouncycastle.util.test.TestResult;

public class EncryptedPrivateKeyInfoTest
    extends SimpleTest
{
    String  alg = "1.2.840.113549.1.12.1.3"; // 3 key triple DES with SHA-1

    public void performTest()
        throws Exception
    {
        doTestWithExplicitIV();

            KeyPairGenerator fact = KeyPairGenerator.getInstance("RSA", "BC");
            fact.initialize(512, new SecureRandom());

            KeyPair keyPair = fact.generateKeyPair();

            PrivateKey  priKey = keyPair.getPrivate();
            PublicKey   pubKey = keyPair.getPublic();

            //
            // set up the parameters
            //
            byte[]              salt = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };
            int                 iterationCount = 100;
            PBEParameterSpec    defParams = new PBEParameterSpec(salt, iterationCount);

            AlgorithmParameters params = AlgorithmParameters.getInstance(alg, "BC");

            params.init(defParams);

            //
            // set up the key
            //
            char[]  password1 = { 'h', 'e', 'l', 'l', 'o' };

            PBEKeySpec          pbeSpec = new PBEKeySpec(password1);
            SecretKeyFactory    keyFact = SecretKeyFactory.getInstance(alg, "BC");
            Cipher cipher = Cipher.getInstance(alg, "BC");

            cipher.init(Cipher.WRAP_MODE, keyFact.generateSecret(pbeSpec), params);

            byte[] wrappedKey = cipher.wrap(priKey);

            //
            // create encrypted object
            //

            EncryptedPrivateKeyInfo pInfo = new EncryptedPrivateKeyInfo(params, wrappedKey);

            //
            // decryption step
            //
            char[]  password2 = { 'h', 'e', 'l', 'l', 'o' };

            pbeSpec = new PBEKeySpec(password2);

            cipher = Cipher.getInstance(pInfo.getAlgName(), "BC");

            cipher.init(Cipher.DECRYPT_MODE, keyFact.generateSecret(pbeSpec), pInfo.getAlgParameters());

            PKCS8EncodedKeySpec keySpec = pInfo.getKeySpec(cipher);

            if (!MessageDigest.isEqual(priKey.getEncoded(), keySpec.getEncoded()))
            {
                fail("Private key does not match");
            }

            //
            // using Cipher parameters test
            //
            pbeSpec = new PBEKeySpec(password1);
            keyFact = SecretKeyFactory.getInstance(alg, "BC");
            cipher = Cipher.getInstance(alg, "BC");

            cipher.init(Cipher.WRAP_MODE, keyFact.generateSecret(pbeSpec), params);

            wrappedKey = cipher.wrap(priKey);

            //
            // create encrypted object
            //

            pInfo = new EncryptedPrivateKeyInfo(cipher.getParameters(), wrappedKey);

            //
            // decryption step
            //
            pbeSpec = new PBEKeySpec(password2);

            cipher = Cipher.getInstance(pInfo.getAlgName(), "BC");

            cipher.init(Cipher.DECRYPT_MODE, keyFact.generateSecret(pbeSpec), pInfo.getAlgParameters());

            keySpec = pInfo.getKeySpec(cipher);

            if (!MessageDigest.isEqual(priKey.getEncoded(), keySpec.getEncoded()))
            {
               fail("Private key does not match");
            }
    }

    public void doTestWithExplicitIV()
        throws Exception
    {
        KeyPairGenerator fact = KeyPairGenerator.getInstance("RSA", "BC");
        fact.initialize(512, new SecureRandom());

        KeyPair keyPair = fact.generateKeyPair();

        PrivateKey  priKey = keyPair.getPrivate();
        PublicKey   pubKey = keyPair.getPublic();

        //
        // set up the parameters
        //
        byte[]              salt = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };
        int                 iterationCount = 100;
        PBEParameterSpec    defParams = new PBEParameterSpec(salt, iterationCount);

        AlgorithmParameters params = AlgorithmParameters.getInstance(alg, "BC");

        params.init(defParams);

        //
        // set up the key
        //
        char[]  password1 = { 'h', 'e', 'l', 'l', 'o' };

        Cipher              cipher = Cipher.getInstance(alg, "BC");

        byte[] iv = { 1, 2, 3, 4, 5, 6, 7, 8 };

        cipher.init(Cipher.WRAP_MODE, new PKCS12KeyWithParameters(password1, salt, iterationCount), new IvParameterSpec(iv));

        byte[] wrappedKey = cipher.wrap(priKey);

        //
        // create encrypted object
        //

        EncryptedPrivateKeyInfo pInfo = new EncryptedPrivateKeyInfo(params, wrappedKey);

        //
        // decryption step
        //
        char[]  password2 = { 'h', 'e', 'l', 'l', 'o' };

        cipher = Cipher.getInstance(pInfo.getAlgName(), "BC");

        cipher.init(Cipher.DECRYPT_MODE, new PKCS12KeyWithParameters(password2, salt, iterationCount), new IvParameterSpec(iv));

        PKCS8EncodedKeySpec keySpec = pInfo.getKeySpec(cipher);

        if (!MessageDigest.isEqual(priKey.getEncoded(), keySpec.getEncoded()))
        {
            fail("Private key does not match");
        }
    }

    public String getName()
    {
        return "EncryptedPrivateKeyInfoTest";
    }

    public static void main(
        String[]    args)
    {
        Security.addProvider(new BouncyCastleProvider());

        Test            test = new EncryptedPrivateKeyInfoTest();
        TestResult      result = test.perform();

        System.out.println(result.toString());
    }
}
