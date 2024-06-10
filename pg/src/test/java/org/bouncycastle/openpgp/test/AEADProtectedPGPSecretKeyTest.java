package org.bouncycastle.openpgp.test;

import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.bcpg.BCPGInputStream;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.bc.BcPGPObjectFactory;
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import org.bouncycastle.util.encoders.Hex;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Iterator;

public class AEADProtectedPGPSecretKeyTest
        extends AbstractPgpKeyPairTest
{

    @Override
    public String getName()
    {
        return "Argon2ProtectedPGPSecretKeyTest";
    }

    @Override
    public void performTest()
            throws Exception
    {
        unlockTestVector();
    }

    private void unlockTestVector()
            throws IOException, PGPException
    {
        // AEAD encrypted test vector extracted from here:
        // https://www.ietf.org/archive/id/draft-ietf-openpgp-crypto-refresh-13.html#name-sample-locked-v6-secret-key
        String armoredVector = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
                "\n" +
                "xYIGY4d/4xsAAAAg+U2nu0jWCmHlZ3BqZYfQMxmZu52JGggkLq2EVD34laP9JgkC\n" +
                "FARdb9ccngltHraRe25uHuyuAQQVtKipJ0+r5jL4dacGWSAheCWPpITYiyfyIOPS\n" +
                "3gIDyg8f7strd1OB4+LZsUhcIjOMpVHgmiY/IutJkulneoBYwrEGHxsKAAAAQgWC\n" +
                "Y4d/4wMLCQcFFQoOCAwCFgACmwMCHgkiIQbLGGxPBgmml+TVLfpscisMHx4nwYpW\n" +
                "cI9lJewnutmsyQUnCQIHAgAAAACtKCAQPi19In7A5tfORHHbNr/JcIMlNpAnFJin\n" +
                "7wV2wH+q4UWFs7kDsBJ+xP2i8CMEWi7Ha8tPlXGpZR4UruETeh1mhELIj5UeM8T/\n" +
                "0z+5oX1RHu11j8bZzFDLX9eTsgOdWATHggZjh3/jGQAAACCGkySDZ/nlAV25Ivj0\n" +
                "gJXdp4SYfy1ZhbEvutFsr15ENf0mCQIUBA5hhGgp2oaavg6mFUXcFMwBBBUuE8qf\n" +
                "9Ock+xwusd+GAglBr5LVyr/lup3xxQvHXFSjjA2haXfoN6xUGRdDEHI6+uevKjVR\n" +
                "v5oAxgu7eJpaXNjCmwYYGwoAAAAsBYJjh3/jApsMIiEGyxhsTwYJppfk1S36bHIr\n" +
                "DB8eJ8GKVnCPZSXsJ7rZrMkAAAAABAEgpukYbZ1ZNfyP5WMUzbUnSGpaUSD5t2Ki\n" +
                "Nacp8DkBClZRa2c3AMQzSDXa9jGhYzxjzVb5scHDzTkjyRZWRdTq8U6L4da+/+Kt\n" +
                "ruh8m7Xo2ehSSFyWRSuTSZe5tm/KXgYG\n" +
                "-----END PGP PRIVATE KEY BLOCK-----";
        char[] passphrase = "correct horse battery staple".toCharArray();
        // Plaintext vectors extracted from here:
        // https://www.ietf.org/archive/id/draft-ietf-openpgp-crypto-refresh-13.html#name-sample-v6-secret-key-transf
        byte[] plainPrimaryKey = Hex.decode("1972817b12be707e8d5f586ce61361201d344eb266a2c82fde6835762b65b0b7");
        byte[] plainSubkey = Hex.decode("4d600a4f794d44775c57a26e0feefed558e9afffd6ad0d582d57fb2ba2dcedb8");

        ByteArrayInputStream bIn = new ByteArrayInputStream(armoredVector.getBytes(StandardCharsets.UTF_8));
        ArmoredInputStream aIn = new ArmoredInputStream(bIn);
        BCPGInputStream pIn = new BCPGInputStream(aIn);
        PGPObjectFactory objFact = new BcPGPObjectFactory(pIn);
        PGPSecretKeyRing keys = (PGPSecretKeyRing) objFact.nextObject();

        Iterator<PGPSecretKey> it = keys.getSecretKeys();
        PGPSecretKey primaryKey = it.next();
        PGPSecretKey subkey = it.next();

        // Test Bouncy Castle implementation
        BcPBESecretKeyDecryptorBuilder bcDecryptor = new BcPBESecretKeyDecryptorBuilder(new BcPGPDigestCalculatorProvider());
        PGPPrivateKey privPrimaryKey = primaryKey.extractPrivateKey(bcDecryptor.build(passphrase));
        isEncodingEqual(plainPrimaryKey, privPrimaryKey.getPrivateKeyDataPacket().getEncoded());

        // Test Jca/Jce implementation
        JcePBESecretKeyDecryptorBuilder jceDecryptor = new JcePBESecretKeyDecryptorBuilder().setProvider(new BouncyCastleProvider());
        PGPPrivateKey privSubKey = subkey.extractPrivateKey(jceDecryptor.build(passphrase));
        isEncodingEqual(plainSubkey, privSubKey.getPrivateKeyDataPacket().getEncoded());
    }

    public static void main(String[] args)
    {
        runTest(new AEADProtectedPGPSecretKeyTest());
    }
}
