package org.bouncycastle.openpgp.test;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.security.SignatureException;
import java.security.spec.ECGenParameterSpec;
import java.util.Date;
import java.util.Iterator;

import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECNamedDomainParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPKeyRingGenerator;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.bc.BcPGPObjectFactory;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.KeyFingerPrintCalculator;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.bc.BcPGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPKeyPair;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyKeyEncryptionMethodGenerator;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyDataDecryptorFactoryBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.test.SimpleTest;
import org.bouncycastle.util.test.UncloseableOutputStream;

public class PGPECDHTest
    extends SimpleTest
{
    byte[] testPubKey =
        Base64.decode(
            "mFIEUb4GwBMIKoZIzj0DAQcCAwS8p3TFaRAx58qCG63W+UNthXBPSJDnVDPTb/sT" +
            "iXePaAZ/Gh1GKXTq7k6ab/67MMeVFp/EdySumqdWLtvceFKstFBUZXN0IEVDRFNB" +
            "LUVDREggKEtleSBhbmQgc3Via2V5IGFyZSAyNTYgYml0cyBsb25nKSA8dGVzdC5l" +
            "Y2RzYS5lY2RoQGV4YW1wbGUuY29tPoh6BBMTCAAiBQJRvgbAAhsDBgsJCAcDAgYV" +
            "CAIJCgsEFgIDAQIeAQIXgAAKCRD3wDlWjFo9U5O2AQDi89NO6JbaIObC63jMMWsi" +
            "AaQHrBCPkDZLibgNv73DLgD/faouH4YZJs+cONQBPVnP1baG1NpWR5ppN3JULFcr" +
            "hcq4VgRRvgbAEggqhkjOPQMBBwIDBLtY8Nmfz0zSEa8C1snTOWN+VcT8pXPwgJRy" +
            "z6kSP4nPt1xj1lPKj5zwPXKWxMkPO9ocqhKdg2mOh6/rc1ObIoMDAQgHiGEEGBMI" +
            "AAkFAlG+BsACGwwACgkQ98A5VoxaPVN8cgEAj4dMNMNwRSg2ZBWunqUAHqIedVbS" +
            "dmwmbysD192L3z4A/ReXEa0gtv8OFWjuALD1ovEK8TpDORLUb6IuUb5jUIzY");

    byte[] testPrivKey =
        Base64.decode(
            "lKUEUb4GwBMIKoZIzj0DAQcCAwS8p3TFaRAx58qCG63W+UNthXBPSJDnVDPTb/sT" +
            "iXePaAZ/Gh1GKXTq7k6ab/67MMeVFp/EdySumqdWLtvceFKs/gcDAo11YYCae/K2" +
            "1uKGJ/uU4b4QHYnPIsAdYpuo5HIdoAOL/WwduRa8C6vSFrtMJLDqPK3BUpMz3CXN" +
            "GyMhjuaHKP5MPbBZkIfgUGZO5qvU9+i0UFRlc3QgRUNEU0EtRUNESCAoS2V5IGFu" +
            "ZCBzdWJrZXkgYXJlIDI1NiBiaXRzIGxvbmcpIDx0ZXN0LmVjZHNhLmVjZGhAZXhh" +
            "bXBsZS5jb20+iHoEExMIACIFAlG+BsACGwMGCwkIBwMCBhUIAgkKCwQWAgMBAh4B" +
            "AheAAAoJEPfAOVaMWj1Tk7YBAOLz007oltog5sLreMwxayIBpAesEI+QNkuJuA2/" +
            "vcMuAP99qi4fhhkmz5w41AE9Wc/VtobU2lZHmmk3clQsVyuFyg==");

    byte[] testMessage =
        Base64.decode(
            "hH4Dp5+FdoujIBwSAgMErx4BSvgXY3irwthgxU8zPoAoR+8rhmxdpwbw6ZJAO2GX" +
            "azWJ85JNcobHKDeGeUq6wkTFu+g6yG99gIX8J5xJAjBRhyCRcaFgwbdDV4orWTe3" +
            "iewiT8qs4BQ23e0c8t+thdKoK4thMsCJy7wSKqY0sJTSVAELroNbCOi2lcO15YmW" +
            "6HiuFH7VKWcxPUBjXwf5+Z3uOKEp28tBgNyDrdbr1BbqlgYzIKq/pe9zUbUXfitn" +
            "vFc6HcGhvmRQreQ+Yw1x3x0HJeoPwg==");

    private static final byte[] curve25519Message = Base64.decode(
        "hE4Dg5N9lpwvavoSAQdApL1xhvz/28almLuqHjyrzwVRnB+37yODIRZCkfPk"
      + "GEIgd9uff5j8mYbI9ErePgRI47fDnQPu8mI4hTOhe8pHzyXSTwFf5CesSdME"
      + "Td9g+UG6cYt/i+cHQWMQD7a53fMNFxPGVYLUFXC5cQh+KvBPghfdoFQMhbR+"
      + "GDgauMrgtk//Os0WCYWJa7VZkD5ak3sbMwk=");

    private static final byte[] curve25519Pub =    Base64.decode(
        "mDMEXEzydhYJKwYBBAHaRw8BAQdAwHPDYhq7hIsCT0jHNxGh4Mbao9kDkcHZilME" +
        "jfgnnG60N1Rlc3QgS2V5IChEbyBub3QgdXNlIGZvciByZWFsLikgPHRlc3RAd29v" +
        "ZHMtZ2VibGVyLmNvbT6IlgQTFggAPhYhBIuq+f4gKmIa9ZKEqJdUhr00IJstBQJc" +
        "TPJ2AhsDBQkB4TOABQsJCAcCBhUKCQgLAgQWAgMBAh4BAheAAAoJEJdUhr00IJst" +
        "dHAA/RDOjus5OZL2m9Q9dxOVnWNguT7Cr5cWdJxUeKAWE2c6AQCcQZWA4SmV1dkJ" +
        "U0XKmLeu3xWDpqrydT4+vQXb/Qm9B7g4BFxM8nYSCisGAQQBl1UBBQEBB0AY3XTS" +
        "6S1pwFNc1QhNpEKTStG+LAJpiHPK9QyXBbW9dQMBCAeIfgQYFggAJhYhBIuq+f4g" +
        "KmIa9ZKEqJdUhr00IJstBQJcTPJ2AhsMBQkB4TOAAAoJEJdUhr00IJstmAsBAMRJ" +
        "pvh8iegwrJDMoQc53ZqDRsbieElV6ofB80a+jkzZAQCgpAaY4hZc8GUan2JIqkg0" +
        "gs23h4au7H79KqXYG4a+Bg==");

    private static final byte[] curve25519Priv = Base64.decode(
    "lIYEXEzydhYJKwYBBAHaRw8BAQdAwHPDYhq7hIsCT0jHNxGh4Mbao9kDkcHZilME" +
        "jfgnnG7+BwMCgEr7OFDl3dTpT73rmw6vIwiTGqjx+Xbe8cq4l24q2AOtzO+UR97q" +
        "7ypL41jtt7BY7uoxhF+NCKzYEtRoqyaM0lfjDlOVRJP6SYRixK2UHLQ3VGVzdCBL" +
        "ZXkgKERvIG5vdCB1c2UgZm9yIHJlYWwuKSA8dGVzdEB3b29kcy1nZWJsZXIuY29t" +
        "PoiWBBMWCAA+FiEEi6r5/iAqYhr1koSol1SGvTQgmy0FAlxM8nYCGwMFCQHhM4AF" +
        "CwkIBwIGFQoJCAsCBBYCAwECHgECF4AACgkQl1SGvTQgmy10cAD9EM6O6zk5kvab" +
        "1D13E5WdY2C5PsKvlxZ0nFR4oBYTZzoBAJxBlYDhKZXV2QlTRcqYt67fFYOmqvJ1" +
        "Pj69Bdv9Cb0HnIsEXEzydhIKKwYBBAGXVQEFAQEHQBjddNLpLWnAU1zVCE2kQpNK" +
        "0b4sAmmIc8r1DJcFtb11AwEIB/4HAwItKjH+kGqkMelkEdIRxSLFeCsB/A64n+os" +
        "X9nWVYsrixEWT5JcRWBniI1PKt9Cm15Yt8KQSAFDJIj5tnEm28x5RM0CzFHQ9Ej2" +
        "8Q2Lt0RoiH4EGBYIACYWIQSLqvn+ICpiGvWShKiXVIa9NCCbLQUCXEzydgIbDAUJ" +
        "AeEzgAAKCRCXVIa9NCCbLZgLAQDESab4fInoMKyQzKEHOd2ag0bG4nhJVeqHwfNG" +
        "vo5M2QEAoKQGmOIWXPBlGp9iSKpINILNt4eGrux+/Sql2BuGvgY=");

    private static final char[] curve25519Pwd = "foobar".toCharArray();

    private void generate()
        throws Exception
    {
        //
        // Generate a master key
        //
        KeyPairGenerator        keyGen = KeyPairGenerator.getInstance("ECDSA", "BC");

        keyGen.initialize(new ECGenParameterSpec("P-256"));

        KeyPair kpSign = keyGen.generateKeyPair();

        PGPKeyPair ecdsaKeyPair = new JcaPGPKeyPair(PGPPublicKey.ECDSA, kpSign, new Date());

        //
        // Generate an encryption key
        //
        keyGen = KeyPairGenerator.getInstance("ECDH", "BC");

        keyGen.initialize(new ECGenParameterSpec("P-256"));

        KeyPair kpEnc = keyGen.generateKeyPair();

        PGPKeyPair ecdhKeyPair = new JcaPGPKeyPair(PGPPublicKey.ECDH, kpEnc, new Date());

        //
        // generate a key ring
        //
        char[] passPhrase = "test".toCharArray();
        PGPDigestCalculator sha1Calc = new JcaPGPDigestCalculatorProviderBuilder().build().get(HashAlgorithmTags.SHA1);
        PGPKeyRingGenerator keyRingGen = new PGPKeyRingGenerator(PGPSignature.POSITIVE_CERTIFICATION, ecdsaKeyPair,
                 "test@bouncycastle.org", sha1Calc, null, null,
                 new JcaPGPContentSignerBuilder(ecdsaKeyPair.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA1).setProvider("BC"),
                 new JcePBESecretKeyEncryptorBuilder(PGPEncryptedData.AES_256, sha1Calc).setProvider("BC").build(passPhrase));

        keyRingGen.addSubKey(ecdhKeyPair);

        PGPPublicKeyRing pubRing = keyRingGen.generatePublicKeyRing();

        // TODO: add check of KdfParameters
        doBasicKeyRingCheck(pubRing);

        PGPSecretKeyRing secRing = keyRingGen.generateSecretKeyRing();

        KeyFingerPrintCalculator fingerCalc = new JcaKeyFingerprintCalculator();

        PGPPublicKeyRing pubRingEnc = new PGPPublicKeyRing(pubRing.getEncoded(), fingerCalc);

        if (!Arrays.areEqual(pubRing.getEncoded(), pubRingEnc.getEncoded()))
        {
            fail("public key ring encoding failed");
        }

        PGPSecretKeyRing secRingEnc = new PGPSecretKeyRing(secRing.getEncoded(), fingerCalc);

        if (!Arrays.areEqual(secRing.getEncoded(), secRingEnc.getEncoded()))
        {
            fail("secret key ring encoding failed");
        }

        PGPPrivateKey pgpPrivKey = secRing.getSecretKey().extractPrivateKey(new JcePBESecretKeyDecryptorBuilder().setProvider("BC").build(passPhrase));
    }

    private void testCurve25519Message()
        throws Exception
    {
        PGPSecretKeyRing ring = new PGPSecretKeyRing(curve25519Priv, new JcaKeyFingerprintCalculator());

        JcaPGPObjectFactory pgpF = new JcaPGPObjectFactory(curve25519Message);

        PGPEncryptedDataList encList = (PGPEncryptedDataList)pgpF.nextObject();

        PGPPublicKeyEncryptedData encP = (PGPPublicKeyEncryptedData)encList.get(0);

        InputStream clear = encP.getDataStream(new JcePublicKeyDataDecryptorFactoryBuilder().setProvider("BC").build(ring.getSecretKey(encP.getKeyID())
            .extractPrivateKey(new JcePBESecretKeyDecryptorBuilder().setProvider("BC").build(curve25519Pwd))));

        pgpF = new JcaPGPObjectFactory(clear);

        PGPCompressedData cd = (PGPCompressedData)pgpF.nextObject();

        PGPLiteralData ld = (PGPLiteralData)new JcaPGPObjectFactory(cd.getDataStream()).nextObject();

        clear = ld.getInputStream();
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        int ch;
        while ((ch = clear.read()) >= 0)
        {
            bOut.write(ch);
        }

        byte[] out = bOut.toByteArray();

        if (!areEqual(out, Strings.toByteArray("Hello world\n")))
        {
            fail("wrong plain text in generated packet");
        }
    }

    private void testCurve25519MessageBc()
        throws Exception
    {
        PGPSecretKeyRing ring = new PGPSecretKeyRing(curve25519Priv, new BcKeyFingerprintCalculator());

        BcPGPObjectFactory pgpF = new BcPGPObjectFactory(curve25519Message);

        PGPEncryptedDataList encList = (PGPEncryptedDataList)pgpF.nextObject();

        PGPPublicKeyEncryptedData encP = (PGPPublicKeyEncryptedData)encList.get(0);

        InputStream clear = encP.getDataStream(new BcPublicKeyDataDecryptorFactory(ring.getSecretKey(encP.getKeyID())
            .extractPrivateKey(new JcePBESecretKeyDecryptorBuilder().setProvider("BC").build(curve25519Pwd))));

        pgpF = new BcPGPObjectFactory(clear);

        PGPCompressedData cd = (PGPCompressedData)pgpF.nextObject();

        PGPLiteralData ld = (PGPLiteralData)new BcPGPObjectFactory(cd.getDataStream()).nextObject();

        clear = ld.getInputStream();
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        int ch;
        while ((ch = clear.read()) >= 0)
        {
            bOut.write(ch);
        }

        byte[] out = bOut.toByteArray();

        if (!areEqual(out, Strings.toByteArray("Hello world\n")))
        {
            fail("wrong plain text in generated packet");
        }
    }

    private void testDecrypt(PGPSecretKeyRing secretKeyRing)
        throws Exception
    {
        JcaPGPObjectFactory pgpF = new JcaPGPObjectFactory(testMessage);

        PGPEncryptedDataList encList = (PGPEncryptedDataList)pgpF.nextObject();

        PGPPublicKeyEncryptedData encP = (PGPPublicKeyEncryptedData)encList.get(0);

        PGPSecretKey secretKey = secretKeyRing.getSecretKey(); // secretKeyRing.getSecretKey(encP.getKeyID());

//        PGPPrivateKey pgpPrivKey = secretKey.extractPrivateKey(new JcePBESecretKeyEncryptorBuilder());

//        clear = encP.getDataStream(pgpPrivKey, "BC");
//
//        bOut.reset();
//
//        while ((ch = clear.read()) >= 0)
//        {
//            bOut.write(ch);
//        }
//
//        out = bOut.toByteArray();
//
//        if (!areEqual(out, text))
//        {
//            fail("wrong plain text in generated packet");
//        }
    }

    private void encryptDecryptTest()
        throws Exception
    {
        byte[]    text = { (byte)'h', (byte)'e', (byte)'l', (byte)'l', (byte)'o', (byte)' ', (byte)'w', (byte)'o', (byte)'r', (byte)'l', (byte)'d', (byte)'!', (byte)'\n' };


        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("ECDH", "BC");

        keyGen.initialize(new ECGenParameterSpec("P-256"));

        KeyPair kpEnc = keyGen.generateKeyPair();

        PGPKeyPair ecdhKeyPair = new JcaPGPKeyPair(PGPPublicKey.ECDH, kpEnc, new Date());

        PGPLiteralDataGenerator lData = new PGPLiteralDataGenerator();
        ByteArrayOutputStream   ldOut = new ByteArrayOutputStream();
        OutputStream pOut = lData.open(ldOut, PGPLiteralDataGenerator.UTF8, PGPLiteralData.CONSOLE, text.length, new Date());

        pOut.write(text);

        pOut.close();

        byte[] data = ldOut.toByteArray();

        ByteArrayOutputStream cbOut = new ByteArrayOutputStream();

        PGPEncryptedDataGenerator cPk = new PGPEncryptedDataGenerator(new JcePGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.CAST5).setProvider("BC").setSecureRandom(new SecureRandom()));

        cPk.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(ecdhKeyPair.getPublicKey()).setProvider("BC"));

        OutputStream cOut = cPk.open(new UncloseableOutputStream(cbOut), data.length);

        cOut.write(data);

        cOut.close();

        JcaPGPObjectFactory pgpF = new JcaPGPObjectFactory(cbOut.toByteArray());

        PGPEncryptedDataList encList = (PGPEncryptedDataList)pgpF.nextObject();

        PGPPublicKeyEncryptedData encP = (PGPPublicKeyEncryptedData)encList.get(0);

        InputStream clear = encP.getDataStream(new JcePublicKeyDataDecryptorFactoryBuilder().setProvider("BC").build(ecdhKeyPair.getPrivateKey()));

        pgpF = new JcaPGPObjectFactory(clear);

        PGPLiteralData ld = (PGPLiteralData)pgpF.nextObject();

        clear = ld.getInputStream();
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        int ch;
        while ((ch = clear.read()) >= 0)
        {
            bOut.write(ch);
        }

        byte[] out = bOut.toByteArray();

        if (!areEqual(out, text))
        {
            fail("wrong plain text in generated packet");
        }
    }

    private void encryptDecryptBCTest(final String curve)
        throws Exception
    {
        byte[]    text = { (byte)'h', (byte)'e', (byte)'l', (byte)'l', (byte)'o', (byte)' ', (byte)'w', (byte)'o', (byte)'r', (byte)'l', (byte)'d', (byte)'!', (byte)'\n' };


        ECKeyPairGenerator keyGen = new ECKeyPairGenerator();

        X9ECParameters x9ECParameters = ECNamedCurveTable.getByName(curve);
        keyGen.init(new ECKeyGenerationParameters(new ECNamedDomainParameters(ECNamedCurveTable.getOID(curve), x9ECParameters.getCurve(), x9ECParameters.getG(), x9ECParameters.getN()), new SecureRandom()));

        AsymmetricCipherKeyPair kpEnc = keyGen.generateKeyPair();

        PGPKeyPair ecdhKeyPair = new BcPGPKeyPair(PGPPublicKey.ECDH, kpEnc, new Date());

        PGPLiteralDataGenerator lData = new PGPLiteralDataGenerator();
        ByteArrayOutputStream   ldOut = new ByteArrayOutputStream();
        OutputStream pOut = lData.open(ldOut, PGPLiteralDataGenerator.UTF8, PGPLiteralData.CONSOLE, text.length, new Date());

        pOut.write(text);

        pOut.close();

        byte[] data = ldOut.toByteArray();

        ByteArrayOutputStream cbOut = new ByteArrayOutputStream();

        PGPEncryptedDataGenerator cPk = new PGPEncryptedDataGenerator(new BcPGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.CAST5).setSecureRandom(new SecureRandom()));

        cPk.addMethod(new BcPublicKeyKeyEncryptionMethodGenerator(ecdhKeyPair.getPublicKey()));

        OutputStream cOut = cPk.open(new UncloseableOutputStream(cbOut), data.length);

        cOut.write(data);

        cOut.close();

        JcaPGPObjectFactory pgpF = new JcaPGPObjectFactory(cbOut.toByteArray());

        PGPEncryptedDataList encList = (PGPEncryptedDataList)pgpF.nextObject();

        PGPPublicKeyEncryptedData encP = (PGPPublicKeyEncryptedData)encList.get(0);

        InputStream clear = encP.getDataStream(new BcPublicKeyDataDecryptorFactory(ecdhKeyPair.getPrivateKey()));

        pgpF = new JcaPGPObjectFactory(clear);

        PGPLiteralData ld = (PGPLiteralData)pgpF.nextObject();

        clear = ld.getInputStream();
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        int ch;
        while ((ch = clear.read()) >= 0)
        {
            bOut.write(ch);
        }

        byte[] out = bOut.toByteArray();

        if (!areEqual(out, text))
        {
            fail("wrong plain text in generated packet");
        }
    }

    public void performTest()
        throws Exception
    {
        //
        // Read the public key
        //
        PGPPublicKeyRing        pubKeyRing = new PGPPublicKeyRing(testPubKey, new JcaKeyFingerprintCalculator());

        doBasicKeyRingCheck(pubKeyRing);

        //
        // Read the private key
        //
        PGPSecretKeyRing        secretKeyRing = new PGPSecretKeyRing(testPrivKey, new JcaKeyFingerprintCalculator());

        testDecrypt(secretKeyRing);

        encryptDecryptTest();
        encryptDecryptBCTest("P-256");
        encryptDecryptBCTest("brainpoolP512r1");

        testCurve25519Message();
        testCurve25519MessageBc();

        generate();
    }

    private void doBasicKeyRingCheck(PGPPublicKeyRing pubKeyRing)
        throws PGPException, SignatureException
    {
        for (Iterator it = pubKeyRing.getPublicKeys(); it.hasNext();)
        {
            PGPPublicKey pubKey = (PGPPublicKey)it.next();

            if (pubKey.isMasterKey())
            {
                if (pubKey.isEncryptionKey())
                {
                    fail("master key showed as encryption key!");
                }
            }
            else
            {
                if (!pubKey.isEncryptionKey())
                {
                    fail("sub key not encryption key!");
                }

                for (Iterator sigIt = pubKeyRing.getPublicKey().getSignatures(); sigIt.hasNext();)
                {
                    PGPSignature certification = (PGPSignature)sigIt.next();

                    certification.init(new JcaPGPContentVerifierBuilderProvider().setProvider("BC"), pubKeyRing.getPublicKey());

                    if (!certification.verifyCertification((String)pubKeyRing.getPublicKey().getUserIDs().next(), pubKeyRing.getPublicKey()))
                    {
                        fail("subkey certification does not verify");
                    }
                }
            }
        }
    }

    public String getName()
    {
        return "PGPECDHTest";
    }

    public static void main(
        String[]    args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new PGPECDHTest());
    }
}
