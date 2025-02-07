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

    }
}
