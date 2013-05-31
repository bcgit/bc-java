package org.bouncycastle.jce.provider.test;

import java.security.Key;
import java.security.SecureRandom;
import java.security.Security;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.IvParameterSpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.test.SimpleTest;

public class SlotTwoTest 
    extends SimpleTest
{
    byte[] plainData = "abcdefghijklmnopqrstuvwxyz".getBytes();

    public String getName()
    {
        return "SlotTwo";
    }

    public void performTest() 
        throws Exception
    {
        Security.removeProvider("BC");
        Security.insertProviderAt(new BouncyCastleProvider(), 2);

        KeyGenerator keyGen = KeyGenerator.getInstance("DESede", "BC");
        
        keyGen.init(new SecureRandom());

        Key key = keyGen.generateKey();

        testDesEde(key, "ECB", "PKCS7Padding");
        testDesEde(key, "CBC", "PKCS7Padding");
        testDesEde(key, "CTR", "NoPadding");
        testDesEde(key, "CTR", "PKCS7Padding");
        testDesEde(key, "OFB", "PKCS7Padding");
        testDesEde(key, "CFB", "PKCS7Padding");
        
        Security.removeProvider("BC");
        Security.addProvider(new BouncyCastleProvider());
    }

    private void testDesEde(
        Key key, 
        String mode, 
        String padding) 
        throws Exception
    {
        Cipher encrypt = Cipher.getInstance("DESede/" + mode + "/" + padding, "BC");
        Cipher decrypt = Cipher.getInstance("DESede/" + mode + "/" + padding);
        
        if (!decrypt.getProvider().getName().equals("BC"))
        {
            fail("BC provider not returned for DESede/" + mode + "/" + padding + " got " + decrypt.getProvider().getName());
        }

        encrypt.init(Cipher.ENCRYPT_MODE, key);

        byte[] encryptedBytes = encrypt.doFinal(plainData);
        byte[] ivBytes = encrypt.getIV();
        
        if (ivBytes != null)
        {
            IvParameterSpec ivp = new IvParameterSpec(ivBytes);
    
            decrypt.init(Cipher.DECRYPT_MODE, key, ivp);
        }
        else
        {
            decrypt.init(Cipher.DECRYPT_MODE, key);
        }

        byte[] plainBytes = decrypt.doFinal(encryptedBytes, 0, encryptedBytes.length);
        
        if (!areEqual(plainData, plainBytes))
        {
            fail("decryption test failed.");
        }
    }
    
    public static void main(
        String[]    args)
    {
        runTest(new SlotTwoTest());
    }
}
