
package org.bouncycastle.jce.provider.test;

import java.security.Key;
import java.security.Security;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SealedObject;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.test.SimpleTestResult;
import org.bouncycastle.util.test.Test;
import org.bouncycastle.util.test.TestResult;

public class SealedTest
    implements Test
{
    final static String provider = "BC";

    public String getName()
    {
        return "SealedObject";
    }

    public TestResult perform()
    {
        try
        {
            KeyGenerator keyGen = KeyGenerator.getInstance("DES", provider);
            Key key = keyGen.generateKey();
            Cipher c = Cipher.getInstance("DES/ECB/PKCS5Padding", provider);

            c.init(Cipher.ENCRYPT_MODE, key);
            String object = "Hello world";
            SealedObject so = new SealedObject(object, c);
            c.init(Cipher.DECRYPT_MODE, key);

            Object o = so.getObject(c);
            if (!o.equals(object))
            {
                return new SimpleTestResult(false, "Result object 1 not equal"
                        + "orig: " + object + " res: " + o);
            }

            o = so.getObject(key);
            if (!o.equals(object))
            {
                return new SimpleTestResult(false, "Result object 2 not equal"
                        + "orig: " + object + " res: " + o);
            }

            o = so.getObject(key, provider);
            if (!o.equals(object))
            {
                return new SimpleTestResult(false, "Result object 3 not equal"
                        + "orig: " + object + " res: " + o);
            }

            return new SimpleTestResult(true, getName() + ": Okay");
        }
        catch (Exception e)
        {
            return new SimpleTestResult(false, getName()
                    + ": failed excpetion - " + e.toString(), e);
        }
    }

    public static void main(String[] args)
    {
        Security.addProvider(new BouncyCastleProvider());

        Test            test = new SealedTest();
        TestResult      result = test.perform();

        System.out.println(result.toString());
    }
}

