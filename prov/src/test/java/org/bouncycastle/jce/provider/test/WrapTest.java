package org.bouncycastle.jce.provider.test;

import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.test.SimpleTestResult;
import org.bouncycastle.util.test.Test;
import org.bouncycastle.util.test.TestResult;

public class WrapTest
    implements Test
{
    public TestResult perform()
    {
        try
        {
            Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding", "BC");
            KeyPairGenerator fact = KeyPairGenerator.getInstance("RSA", "BC");
            fact.initialize(512, new SecureRandom());

            KeyPair keyPair = fact.generateKeyPair();

            PrivateKey  priKey = keyPair.getPrivate();
            PublicKey   pubKey = keyPair.getPublic();

            KeyGenerator keyGen = KeyGenerator.getInstance("DES", "BC");
            Key wrapKey = keyGen.generateKey();
            cipher.init(Cipher.WRAP_MODE, wrapKey);
            byte[] wrappedKey = cipher.wrap(priKey);

            cipher.init(Cipher.UNWRAP_MODE, wrapKey);
            Key key = cipher.unwrap(wrappedKey, "RSA", Cipher.PRIVATE_KEY);

            if (!MessageDigest.isEqual(priKey.getEncoded(), key.getEncoded()))
            {
                return new SimpleTestResult(false, "Unwrapped key does not match");
            }

            return new SimpleTestResult(true, getName() + ": Okay");
        }
        catch (Exception e)
        {
            return new SimpleTestResult(false, getName() + ": exception - " + e.toString(), e);
        }
    }

    public String getName()
    {
        return "WrapTest";
    }

    public static void main(
        String[]    args)
    {
        Security.addProvider(new BouncyCastleProvider());

        Test            test = new WrapTest();
        TestResult      result = test.perform();

        System.out.println(result.toString());
        if (result.getException() != null)
        {
            result.getException().printStackTrace();
        }
    }
}
