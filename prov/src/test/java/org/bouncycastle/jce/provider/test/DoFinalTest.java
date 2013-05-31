package org.bouncycastle.jce.provider.test;

import java.security.Key;
import java.security.Security;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.test.SimpleTestResult;
import org.bouncycastle.util.test.Test;
import org.bouncycastle.util.test.TestResult;

/**
 * check that doFinal is properly reseting the cipher.
 */
public class DoFinalTest
    implements Test
{
    public DoFinalTest()
    {
    }

    private boolean equalArray(
        byte[]  a,
        int        aOff,
        byte[]  b,
        int        length)
    {
        if (aOff + a.length < length)
        {
            return false;
        }
        
        if (b.length < length)
        {
            return false;
        }
        
        for (int i = 0; i != length; i++)
        {
            if (a[aOff + i] != b[i])
            {
                return false;
            }
        }

        return true;
    }
    
    public TestResult checkCipher(
        String    cipherName)
    {
        String lCode = "ABCDEFGHIJKLMNOPQRSTUVWXY0123456789";
        String  baseAlgorithm;
        int     index = cipherName.indexOf('/');

        if (index > 0)
        {
            baseAlgorithm = cipherName.substring(0, index);
        }
        else
        {
            baseAlgorithm = cipherName;
        }
        
        try
        {
            KeyGenerator    kGen = KeyGenerator.getInstance(baseAlgorithm, "BC");
            Cipher          cipher = Cipher.getInstance(cipherName, "BC");
            Key             key = kGen.generateKey();

            cipher.init(Cipher.ENCRYPT_MODE, key);

            byte[] encrypted = cipher.doFinal(lCode.getBytes());

            // 2nd try
            byte[]    encrypted2 = cipher.doFinal(lCode.getBytes());

            if (encrypted.length != encrypted2.length)
            {
                return new SimpleTestResult(false, getName() + ": Failed " + cipherName + " - expected length " + encrypted.length + " got " + encrypted2.length);
            }

            if (!equalArray(encrypted, 0, encrypted2, encrypted.length))
            {
                return new SimpleTestResult(false, getName() + ": Failed " + cipherName + " - first two arrays not equal");
            }
            
            // 3rd try
            byte[]  enc1 = cipher.update(lCode.getBytes());
            byte[]  enc2 = cipher.doFinal();

            if ((enc1.length + enc2.length) != encrypted.length)
            {
                return new SimpleTestResult(false, getName() + ": Failed " + cipherName + " - expected length " + encrypted.length + " got " + (enc1.length + enc2.length));
            }

            if (!equalArray(encrypted, 0, enc1, enc1.length))
            {
                return new SimpleTestResult(false, getName() + ": Failed " + cipherName + " - enc1 array not equal");
            }
            
            if (!equalArray(encrypted, enc1.length, enc2, enc2.length))
            {
                return new SimpleTestResult(false, getName() + ": Failed " + cipherName + " - enc1 array not equal");
            }
            
            enc1 = cipher.update(lCode.getBytes());
            
            if (!equalArray(encrypted, 0, enc1, enc1.length))
            {
                return new SimpleTestResult(false, getName() + ": Failed " + cipherName + " - 2nd enc1 array not equal");
            }
            
            int len = cipher.doFinal(enc1, 0);
            if ((enc1.length + len) != encrypted.length)
            {
                return new SimpleTestResult(false, getName() + ": Failed " + cipherName + " - expected length " + encrypted.length + " got " + (enc1.length + len));
            }
        }
        catch (Exception e)
        {
            return new SimpleTestResult(false, getName() + ": Failed " + cipherName + " - exception " + e.toString());
        }

        return new SimpleTestResult(true, getName() + ": Okay");
    }

    public TestResult perform()
    {
        TestResult    result = checkCipher("RC4");
        
        if (!result.isSuccessful())
        {
            return result;
        }
        
        result = checkCipher("DES/CBC/PKCS5Padding");
        
        if (!result.isSuccessful())
        {
            return result;
        }
        
        return checkCipher("Rijndael");
    }
    
    public String getName()
    {
        return "DoFinalTest";
    }

    public static void main(
        String[]    args)
    {
        Security.addProvider(new BouncyCastleProvider());

        Test            test = new DoFinalTest();
        TestResult      result = test.perform();

        System.out.println(result.toString());
    }
}
