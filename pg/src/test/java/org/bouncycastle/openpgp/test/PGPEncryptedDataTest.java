package org.bouncycastle.openpgp.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Date;

import org.bouncycastle.bcpg.AEADAlgorithmTags;
import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPPBEEncryptedData;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair;
import org.bouncycastle.openpgp.operator.jcajce.JcePBEDataDecryptorFactoryBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePBEKeyEncryptionMethodGenerator;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyDataDecryptorFactoryBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.io.Streams;
import org.bouncycastle.util.test.SimpleTest;

public class PGPEncryptedDataTest
    extends SimpleTest
{
    @Override
    public String getName()
    {
        return "PGPEncryptedData";
    }

    public void performTest()
        throws Exception
    {
        encryptDecryptTest();
        encryptDecryptMultiChunkTest();
        encryptDecryptMultiChunkBoundaryTest();
        knownDataTest();
        testIntegrityCheckedData();
    }

    private void encryptDecryptTest()
        throws IOException, PGPException
    {
        char[] pass = "AEAD".toCharArray();
        byte[] msg = Strings.toByteArray("Hello, AEAD!");

        ByteArrayOutputStream cbOut = new ByteArrayOutputStream();
        JcePGPDataEncryptorBuilder encryptorBuilder = new JcePGPDataEncryptorBuilder(PGPEncryptedData.AES_128).setSecureRandom(new SecureRandom()).setProvider("BC");

        encryptorBuilder.setUseV5AEAD();
        encryptorBuilder.setWithAEAD(AEADAlgorithmTags.OCB, 10);

        PGPEncryptedDataGenerator cPk = new PGPEncryptedDataGenerator(encryptorBuilder);

        cPk.addMethod(new JcePBEKeyEncryptionMethodGenerator(pass).setProvider("BC"));

        ByteArrayOutputStream ldbOut = new ByteArrayOutputStream();
        PGPLiteralDataGenerator ldGen = new PGPLiteralDataGenerator();

        OutputStream ldOut = ldGen.open(ldbOut, PGPLiteralData.BINARY, PGPLiteralData.CONSOLE, (long)msg.length, new Date());

        ldOut.write(msg);

        ldOut.close();

        byte[] litData = ldbOut.toByteArray();

        OutputStream cOut = cPk.open(cbOut, litData.length);

        cOut.write(litData);

        cOut.close();
        
        // decrypt
        PGPObjectFactory oIn = new JcaPGPObjectFactory(new ByteArrayInputStream(cbOut.toByteArray()));

        PGPEncryptedDataList encList = (PGPEncryptedDataList)oIn.nextObject();

        PGPPBEEncryptedData encP = (PGPPBEEncryptedData)encList.get(0);

        InputStream clear = encP.getDataStream(new JcePBEDataDecryptorFactoryBuilder().setProvider("BC").build(pass));

       // System.err.println(Hex.toHexString(Streams.readAll(clear)));
        PGPObjectFactory pgpFact = new JcaPGPObjectFactory(clear);

        PGPLiteralData ld = (PGPLiteralData)pgpFact.nextObject();

        isEquals("wrong filename", PGPLiteralData.CONSOLE, ld.getFileName());

        byte[] data = Streams.readAll(ld.getDataStream());

        isTrue(Strings.fromUTF8ByteArray(data), Arrays.areEqual(msg, data));
    }

    private void encryptDecryptMultiChunkTest()
        throws Exception
    {
        SecureRandom random = new SecureRandom();
        byte[] msg = new byte[60000];

        random.nextBytes(msg);

        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA", "BC");

        kpGen.initialize(2048);

        PGPKeyPair pgpKp = new JcaPGPKeyPair(PGPPublicKey.RSA_GENERAL , kpGen.generateKeyPair(), new Date());

        PGPPublicKey pubKey = pgpKp.getPublicKey();

        PGPPrivateKey privKey = pgpKp.getPrivateKey();

        ByteArrayOutputStream cbOut = new ByteArrayOutputStream();
        JcePGPDataEncryptorBuilder encryptorBuilder = new JcePGPDataEncryptorBuilder(PGPEncryptedData.AES_128).setSecureRandom(random).setProvider("BC");

        encryptorBuilder.setUseV5AEAD();
        encryptorBuilder.setWithAEAD(AEADAlgorithmTags.OCB, 6);

        PGPEncryptedDataGenerator cPk = new PGPEncryptedDataGenerator(encryptorBuilder);

        cPk.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(pubKey).setProvider("BC"));

        ByteArrayOutputStream ldbOut = new ByteArrayOutputStream();
        PGPLiteralDataGenerator ldGen = new PGPLiteralDataGenerator();

        OutputStream ldOut = ldGen.open(ldbOut, PGPLiteralData.BINARY, PGPLiteralData.CONSOLE, (long)msg.length, new Date());

        ldOut.write(msg);

        ldOut.close();

        byte[] litData = ldbOut.toByteArray();

        OutputStream cOut = cPk.open(cbOut, litData.length);

        cOut.write(litData);

        cOut.close();

        // decrypt
        PGPObjectFactory oIn = new JcaPGPObjectFactory(new ByteArrayInputStream(cbOut.toByteArray()));

        PGPEncryptedDataList encList = (PGPEncryptedDataList)oIn.nextObject();

        PGPPublicKeyEncryptedData encP = (PGPPublicKeyEncryptedData)encList.get(0);

        InputStream clear = encP.getDataStream(new JcePublicKeyDataDecryptorFactoryBuilder().setProvider("BC").build(privKey));

        // System.err.println(Hex.toHexString(Streams.readAll(clear)));
        PGPObjectFactory pgpFact = new JcaPGPObjectFactory(clear);

        PGPLiteralData ld = (PGPLiteralData)pgpFact.nextObject();

        isEquals("wrong filename", PGPLiteralData.CONSOLE, ld.getFileName());

        byte[] data = Streams.readAll(ld.getDataStream());

        isTrue("msg mismatch", Arrays.areEqual(msg, data));
    }

    // check for exact multiple of chunks in encryption
    private void encryptDecryptMultiChunkBoundaryTest()
        throws Exception
    {
        SecureRandom random = new SecureRandom();
        byte[] msg = new byte[(1 << 6) * 5 - 17];     // take of literal data header

        random.nextBytes(msg);

        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA", "BC");

        kpGen.initialize(2048);

        PGPKeyPair pgpKp = new JcaPGPKeyPair(PGPPublicKey.RSA_GENERAL , kpGen.generateKeyPair(), new Date());

        PGPPublicKey pubKey = pgpKp.getPublicKey();

        PGPPrivateKey privKey = pgpKp.getPrivateKey();

        ByteArrayOutputStream cbOut = new ByteArrayOutputStream();
        JcePGPDataEncryptorBuilder encryptorBuilder = new JcePGPDataEncryptorBuilder(PGPEncryptedData.AES_128).setSecureRandom(random).setProvider("BC");

        encryptorBuilder.setUseV5AEAD();
        encryptorBuilder.setWithAEAD(AEADAlgorithmTags.OCB, 6);

        PGPEncryptedDataGenerator cPk = new PGPEncryptedDataGenerator(encryptorBuilder);

        cPk.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(pubKey).setProvider("BC"));

        ByteArrayOutputStream ldbOut = new ByteArrayOutputStream();
        PGPLiteralDataGenerator ldGen = new PGPLiteralDataGenerator();

        OutputStream ldOut = ldGen.open(ldbOut, PGPLiteralData.BINARY, PGPLiteralData.CONSOLE, (long)msg.length, new Date());

        ldOut.write(msg);

        ldOut.close();

        byte[] litData = ldbOut.toByteArray();

        OutputStream cOut = cPk.open(cbOut, litData.length);

        cOut.write(litData);

        cOut.close();

        // decrypt
        PGPObjectFactory oIn = new JcaPGPObjectFactory(new ByteArrayInputStream(cbOut.toByteArray()));

        PGPEncryptedDataList encList = (PGPEncryptedDataList)oIn.nextObject();

        PGPPublicKeyEncryptedData encP = (PGPPublicKeyEncryptedData)encList.get(0);

        InputStream clear = encP.getDataStream(new JcePublicKeyDataDecryptorFactoryBuilder().setProvider("BC").build(privKey));

        // System.err.println(Hex.toHexString(Streams.readAll(clear)));
        PGPObjectFactory pgpFact = new JcaPGPObjectFactory(clear);

        PGPLiteralData ld = (PGPLiteralData)pgpFact.nextObject();

        isEquals("wrong filename", PGPLiteralData.CONSOLE, ld.getFileName());

        byte[] data = Streams.readAll(ld.getDataStream());

        isTrue("msg mismatch", Arrays.areEqual(msg, data));
    }

    private void knownDataTest()
        throws IOException, PGPException
    {
        // AEAD Test
        byte[] key = Base64.decode("lIYEYtpQnxYJKwYBBAHaRw8BAQdA207jla1mpSFwMxffhBxMCar0p8rogMEoeLJd\n" +
            "sCPM0tn+BwMCpoW0UFliSk3SkECmD5cAbHhojoHeiCmT1xmGLt7PIkzzhX6/t96n\n" +
            "arb3JTQMOWltqbt8gLuRjdRuYmliUcPr19SPvepnvqhwLqcOEbbQorQbVGVzdCBU\n" +
            "ZXN0ZXIgPHRlc3RAdGVzdC5jb20+iJkEExYIAEEWIQSqx6vJaSbUECwYQX+L2Dcj\n" +
            "JcwH4AUCYtpQnwIbAwUJA8JnAAULCQgHAgIiAgYVCgkICwIEFgIDAQIeBwIXgAAK\n" +
            "CRCL2DcjJcwH4BQaAQDxal5Q37MSY5EIauKat5fW8j76EwWbMQKadU44Aud2MQD9\n" +
            "FpYCHOh9TkNRfnmnImoxSmeSM0FJOORtPTgh6sxb1QmciwRi2lCfEgorBgEEAZdV\n" +
            "AQUBAQdAkrGtbXYvPKFZBwH6WiFKFE1z+0QplQQMFGlPn4oLUXMDAQgH/gcDAj+y\n" +
            "CtAcASIU0hkO9Ua0ZPO7jyCpQIuI62G5CAUOZTxtnnWOZmmveiJyFu8Vlow4CJoS\n" +
            "KaHc+UeCEPnlb1zLNTW9Icc+OTr/G3HeAKKRM9mIfgQYFggAJhYhBKrHq8lpJtQQ\n" +
            "LBhBf4vYNyMlzAfgBQJi2lCfAhsMBQkDwmcAAAoJEIvYNyMlzAfgMZgA/Ani2Xh2\n" +
            "tU49kjLEFGW4tFOy5PLI8yqqhqDgTdHXo5b5APsH4Q2+dTJdJOzEXsPtlRtwijdA\n" +
            "XNOF3zCe4gEzYO3KDw==");
        byte[] msg = Base64.decode("hE4D4e5Iwh6WdeASAQdA9DbvpCwdd9KykHdl1L/pvbSeuFWzhCLoCibP7+WCM2Ag\n" +
            "ut1kdKQcPo87xfRybK+LM1esJLfY++R9Lx+KxblnKInUVwEHAhBIb1CMxge1v4iZ\n" +
            "SkwYIE/J8MjOyHtwM0koCtKY0Vq8D6LSmLXNCmBvYuqRDOEaJLHiq++RHMrEv7oT\n" +
            "o41RqX9OLFu4/ZAwoL1mABtJIy0B2teibg==");

        PGPSecretKeyRing rng = new PGPSecretKeyRing(new ByteArrayInputStream(key), new JcaKeyFingerprintCalculator());
        PGPObjectFactory oIn = new JcaPGPObjectFactory(new ByteArrayInputStream(msg));

        PGPEncryptedDataList encList = (PGPEncryptedDataList)oIn.nextObject();

        PGPPublicKeyEncryptedData encP = (PGPPublicKeyEncryptedData)encList.get(0);

        InputStream clear = encP.getDataStream(new JcePublicKeyDataDecryptorFactoryBuilder().setProvider("BC").build(rng.getSecretKey(encP.getKeyID()).extractPrivateKey(new JcePBESecretKeyDecryptorBuilder().setProvider("BC").build("Test".toCharArray()))));

        PGPObjectFactory pgpFact = new JcaPGPObjectFactory(clear);

        PGPCompressedData c1 = (PGPCompressedData)pgpFact.nextObject();

        pgpFact = new JcaPGPObjectFactory(c1.getDataStream());

        PGPLiteralData ld = (PGPLiteralData)pgpFact.nextObject();

        isEquals("wrong filename", "Test.txt", ld.getFileName());

        byte[] data = Streams.readAll(ld.getDataStream());

        isTrue(Arrays.areEqual(Strings.toByteArray("Test Content"), data));
    }

    private void testIntegrityCheckedData()
        throws IOException, PGPException
    {
        PGPSecretKeyRing rng = (PGPSecretKeyRing)new PGPObjectFactory(new ArmoredInputStream(this.getClass().getResourceAsStream("encd-test-key.asc")), new JcaKeyFingerprintCalculator()).nextObject();
        byte[] msg = Streams.readAll(this.getClass().getResourceAsStream("encd-test-data.pgp"));

        PGPObjectFactory oIn = new JcaPGPObjectFactory(new ByteArrayInputStream(msg));

        PGPEncryptedDataList encList = (PGPEncryptedDataList)oIn.nextObject();

        PGPPublicKeyEncryptedData encP = (PGPPublicKeyEncryptedData)encList.get(0);

        InputStream clear = encP.getDataStream(new JcePublicKeyDataDecryptorFactoryBuilder()
            .setProvider("BC").build(rng.getSecretKey(encP.getKeyID())
                .extractPrivateKey(new JcePBESecretKeyDecryptorBuilder().setProvider("BC").build("tkhbackup".toCharArray()))));

        PGPObjectFactory pgpFact = new JcaPGPObjectFactory(clear);

        PGPCompressedData c1 = (PGPCompressedData)pgpFact.nextObject();

        pgpFact = new JcaPGPObjectFactory(c1.getDataStream());

        PGPLiteralData ld = (PGPLiteralData)pgpFact.nextObject();

        isEquals("wrong filename", "", ld.getFileName());

        String data = Strings.fromByteArray(Streams.readAll(ld.getDataStream()));

        isTrue(data.startsWith("<?xml version=\"1.0\" ?>"));
    }

    public static void main(
        String[]    args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new PGPEncryptedDataTest());
    }
}
