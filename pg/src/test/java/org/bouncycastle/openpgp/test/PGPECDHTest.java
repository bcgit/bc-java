package org.bouncycastle.openpgp.test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.SignatureException;
import java.security.spec.ECGenParameterSpec;
import java.util.Date;
import java.util.Iterator;

import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPKeyRingGenerator;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.KeyFingerPrintCalculator;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyEncryptorBuilder;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.test.SimpleTest;

public class PGPECDHTest
    extends SimpleTest
{
    byte[] testPubKey =
        Base64.decode(
            "mFIEUb4GwBMIKoZIzj0DAQcCAwS8p3TFaRAx58qCG63W+UNthXBPSJDnVDPTb/sT\n" +
            "iXePaAZ/Gh1GKXTq7k6ab/67MMeVFp/EdySumqdWLtvceFKstFBUZXN0IEVDRFNB\n" +
            "LUVDREggKEtleSBhbmQgc3Via2V5IGFyZSAyNTYgYml0cyBsb25nKSA8dGVzdC5l\n" +
            "Y2RzYS5lY2RoQGV4YW1wbGUuY29tPoh6BBMTCAAiBQJRvgbAAhsDBgsJCAcDAgYV\n" +
            "CAIJCgsEFgIDAQIeAQIXgAAKCRD3wDlWjFo9U5O2AQDi89NO6JbaIObC63jMMWsi\n" +
            "AaQHrBCPkDZLibgNv73DLgD/faouH4YZJs+cONQBPVnP1baG1NpWR5ppN3JULFcr\n" +
            "hcq4VgRRvgbAEggqhkjOPQMBBwIDBLtY8Nmfz0zSEa8C1snTOWN+VcT8pXPwgJRy\n" +
            "z6kSP4nPt1xj1lPKj5zwPXKWxMkPO9ocqhKdg2mOh6/rc1ObIoMDAQgHiGEEGBMI\n" +
            "AAkFAlG+BsACGwwACgkQ98A5VoxaPVN8cgEAj4dMNMNwRSg2ZBWunqUAHqIedVbS\n" +
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

    public void performTest()
        throws Exception
    {
        PGPUtil.setDefaultProvider("BC");

        //
        // Read the public key
        //
        PGPPublicKeyRing        pubKeyRing = new PGPPublicKeyRing(testPubKey, new JcaKeyFingerprintCalculator());

        doBasicKeyRingCheck(pubKeyRing);

        //
        // Read the private key
        //
        PGPSecretKeyRing        secretKeyRing = new PGPSecretKeyRing(testPrivKey, new JcaKeyFingerprintCalculator());

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
