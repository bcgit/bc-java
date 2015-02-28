package org.bouncycastle.openpgp.test;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.security.SignatureException;
import org.bouncycastle.jce.spec.ECNamedCurveGenParameterSpec;
import java.util.Date;
import java.util.Iterator;

import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPKeyRingGenerator;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.KeyFingerPrintCalculator;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyDataDecryptorFactoryBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;
import org.bouncycastle.util.Arrays;
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

    private void generate()
        throws Exception
    {
        //
        // Generate a master key
        //
        KeyPairGenerator        keyGen = KeyPairGenerator.getInstance("ECDSA", "BC");

        keyGen.initialize(256);

        KeyPair kpSign = keyGen.generateKeyPair();

        PGPKeyPair ecdsaKeyPair = new JcaPGPKeyPair(PGPPublicKey.ECDSA, kpSign, new Date());

        //
        // Generate an encryption key
        //
        keyGen = KeyPairGenerator.getInstance("ECDH", "BC");

        keyGen.initialize(256);

        KeyPair kpEnc = keyGen.generateKeyPair();

        PGPKeyPair ecdhKeyPair = new JcaPGPKeyPair(PGPPublicKey.ECDH, kpEnc, new Date());

        //
        // generate a key ring
        //
        char[] passPhrase = "test".toCharArray();
        PGPDigestCalculator sha1Calc = new JcaPGPDigestCalculatorProviderBuilder().build().get(HashAlgorithmTags.SHA1);
        PGPKeyRingGenerator keyRingGen = new PGPKeyRingGenerator(PGPSignature.POSITIVE_CERTIFICATION, ecdsaKeyPair,
                 "test@bouncycastle.org", sha1Calc, null, null,
                 new JcaPGPContentSignerBuilder(ecdsaKeyPair.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA1),
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
    }

    private void testDecrypt(PGPSecretKeyRing secretKeyRing)
        throws Exception
    {
        PGPObjectFactory pgpF = new PGPObjectFactory(testMessage, new BcKeyFingerprintCalculator());

        PGPEncryptedDataList encList = (PGPEncryptedDataList)pgpF.nextObject();

        PGPPublicKeyEncryptedData encP = (PGPPublicKeyEncryptedData)encList.get(0);

        PGPSecretKey secretKey = secretKeyRing.getSecretKey(); // secretKeyRing.getSecretKey(encP.getKeyID());
//
//        PGPPrivateKey pgpPrivKey = secretKey.extractPrivateKey()extractPrivateKey(null);
//
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

        keyGen.initialize(256);

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

        PGPObjectFactory pgpF = new PGPObjectFactory(cbOut.toByteArray(), new BcKeyFingerprintCalculator());

        PGPEncryptedDataList encList = (PGPEncryptedDataList)pgpF.nextObject();

        PGPPublicKeyEncryptedData encP = (PGPPublicKeyEncryptedData)encList.get(0);

        InputStream clear = encP.getDataStream(new JcePublicKeyDataDecryptorFactoryBuilder().setProvider("BC").build(ecdhKeyPair.getPrivateKey()));

        pgpF = new PGPObjectFactory(clear, new BcKeyFingerprintCalculator());

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
