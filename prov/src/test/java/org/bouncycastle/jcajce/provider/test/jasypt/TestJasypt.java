package org.bouncycastle.jcajce.provider.test.jasypt;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class TestJasypt
{
    public static void main(String[] args)
    {
        StandardPBEStringEncryptor stringEncryptor = new StandardPBEStringEncryptor();
        stringEncryptor.setAlgorithm("PBEWITHSHA256AND256BITAES-CBC-BC");
        stringEncryptor.setPassword("secretPassword");
        stringEncryptor.setIvGenerator(new RandomIvGenerator());
        stringEncryptor.setProvider(new BouncyCastleProvider());

        String encryptedText = stringEncryptor.encrypt("plainText");

        StandardPBEStringEncryptor stringdecryptor = new StandardPBEStringEncryptor();
        stringdecryptor.setAlgorithm("PBEWITHSHA256AND256BITAES-CBC-BC");
        stringdecryptor.setPassword("secretPassword");
        stringdecryptor.setIvGenerator(new RandomIvGenerator());
        stringdecryptor.setProvider(new BouncyCastleProvider());

        String decryptedText = stringdecryptor.decrypt(encryptedText);
        System.out.println(decryptedText);

    }
}
