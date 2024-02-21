package org.bouncycastle.openpgp.test;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;
import java.util.Date;
import java.util.Iterator;

import org.bouncycastle.bcpg.AEADAlgorithmTags;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyPacket;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.generators.X448KeyPairGenerator;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveGenParameterSpec;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKdfParameters;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPKeyRingGenerator;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.bc.BcPGPObjectFactory;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.PGPContentVerifier;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.bc.BcPGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.bc.BcPGPKeyConverter;
import org.bouncycastle.openpgp.operator.bc.BcPGPKeyPair;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyKeyEncryptionMethodGenerator;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyConverter;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyDataDecryptorFactoryBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;
import org.bouncycastle.util.test.SimpleTest;
import org.bouncycastle.util.test.UncloseableOutputStream;

public class OperatorBcTest
    extends SimpleTest
{
    public static void main(String[] args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new OperatorBcTest());
    }

    @Override
    public String getName()
    {
        return "OperatorBcTest";
    }

    @Override
    public void performTest()
        throws Exception
    {
        testKeyRings();
        testBcPGPKeyPair();
        testBcPGPDataEncryptorBuilder();
        testBcPGPContentVerifierBuilderProvider();
        //testBcPBESecretKeyDecryptorBuilder();
        testBcKeyFingerprintCalculator();
    }

    public void testBcKeyFingerprintCalculator()
        throws Exception
    {
        final BcKeyFingerprintCalculator calculator = new BcKeyFingerprintCalculator();
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA", "BC");
        kpGen.initialize(1024);
        KeyPair kp = kpGen.generateKeyPair();

        JcaPGPKeyConverter converter = new JcaPGPKeyConverter().setProvider(new BouncyCastleProvider());
        final PGPPublicKey pubKey = converter.getPGPPublicKey(PublicKeyAlgorithmTags.RSA_GENERAL, kp.getPublic(), new Date());

        PublicKeyPacket pubKeyPacket = new PublicKeyPacket(6, PublicKeyAlgorithmTags.RSA_GENERAL, new Date(), pubKey.getPublicKeyPacket().getKey());
        byte[] output = calculator.calculateFingerprint(new PublicKeyPacket(6, PublicKeyAlgorithmTags.RSA_GENERAL, new Date(), pubKey.getPublicKeyPacket().getKey()));
        byte[] kBytes = pubKeyPacket.getEncodedContents();
        SHA256Digest digest = new SHA256Digest();

        digest.update((byte)0x9b);

        digest.update((byte)(kBytes.length >> 24));
        digest.update((byte)(kBytes.length >> 16));
        digest.update((byte)(kBytes.length >> 8));
        digest.update((byte)kBytes.length);

        digest.update(kBytes, 0, kBytes.length);
        byte[] digBuf = new byte[digest.getDigestSize()];

        digest.doFinal(digBuf, 0);
        isTrue(areEqual(output, digBuf));

        final PublicKeyPacket pubKeyPacket2 = new PublicKeyPacket(5, PublicKeyAlgorithmTags.RSA_GENERAL, new Date(), pubKey.getPublicKeyPacket().getKey());
        testException("Unsupported PGP key version: ", "UnsupportedPacketVersionException", () -> calculator.calculateFingerprint(pubKeyPacket2));
    }

//    public void testBcPBESecretKeyDecryptorBuilder()
//        throws PGPException
//    {
//        final PBESecretKeyDecryptor decryptor = new BcPBESecretKeyDecryptorBuilder(new BcPGPDigestCalculatorProvider()).build(BcPGPDSAElGamalTest.pass);
//        decryptor.recoverKeyData(SymmetricKeyAlgorithmTags.CAMELLIA_256, new byte[32], new byte[12], new byte[16], 0, 16);
//    }

    public void testBcPGPContentVerifierBuilderProvider()
        throws Exception
    {
        JcaPGPObjectFactory pgpFact = new JcaPGPObjectFactory(BcPGPDSAElGamalTest.testPubKeyRing);
        PGPPublicKeyRing pgpPub = (PGPPublicKeyRing)pgpFact.nextObject();
        PGPPublicKey pubKey = pgpPub.getPublicKey();
        BcPGPContentVerifierBuilderProvider provider = new BcPGPContentVerifierBuilderProvider();
        PGPContentVerifier contentVerifier = provider.get(PublicKeyAlgorithmTags.DSA, HashAlgorithmTags.SHA1).build(pubKey);
        isEquals(contentVerifier.getHashAlgorithm(), HashAlgorithmTags.SHA1);
        isEquals(contentVerifier.getKeyAlgorithm(), PublicKeyAlgorithmTags.DSA);
        isEquals(contentVerifier.getKeyID(), pubKey.getKeyID());
    }

    public void testBcPGPDataEncryptorBuilder()
        throws Exception
    {
        testException("null cipher specified", "IllegalArgumentException", () -> new BcPGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.NULL));

        testException("AEAD algorithms can only be used with AES", "IllegalStateException", () -> new BcPGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.IDEA).setWithAEAD(AEADAlgorithmTags.OCB, 6));

        testException("minimum chunkSize is 6", "IllegalArgumentException", () -> new BcPGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.AES_256).setWithAEAD(AEADAlgorithmTags.OCB, 5));

        testException("invalid parameters:", "PGPException", () -> new BcPGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.AES_256).build(new byte[0]));

        isTrue(new BcPGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.AES_256).setWithIntegrityPacket(false).build(new byte[32]).getIntegrityCalculator() == null);

        isEquals(16, new BcPGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.AES_256).setWithAEAD(AEADAlgorithmTags.OCB, 6).build(new byte[32]).getBlockSize());
    }

    public void testBcPGPKeyPair()
        throws Exception
    {
        testCreateKeyPair(PublicKeyAlgorithmTags.ECDH, PublicKeyAlgorithmTags.X448, "X448");
        testCreateKeyPair(PublicKeyAlgorithmTags.ECDH, PublicKeyAlgorithmTags.X25519, "X25519");
        testCreateKeyPair(PublicKeyAlgorithmTags.X448, PublicKeyAlgorithmTags.ECDH, "X448");
        testCreateKeyPair(PublicKeyAlgorithmTags.X25519, PublicKeyAlgorithmTags.ECDH, "X25519");
        testCreateKeyPair(PublicKeyAlgorithmTags.EDDSA_LEGACY, PublicKeyAlgorithmTags.Ed448, "Ed448");
        testCreateKeyPair(PublicKeyAlgorithmTags.EDDSA_LEGACY, PublicKeyAlgorithmTags.Ed25519, "Ed25519");
        testCreateKeyPair(PublicKeyAlgorithmTags.Ed448, PublicKeyAlgorithmTags.EDDSA_LEGACY, "Ed448");
        testCreateKeyPair(PublicKeyAlgorithmTags.Ed25519, PublicKeyAlgorithmTags.EDDSA_LEGACY, "Ed25519");
        testCreateKeyPair(PublicKeyAlgorithmTags.RSA_GENERAL, "RSA");
        testCreateKeyPair(PublicKeyAlgorithmTags.ELGAMAL_GENERAL, "ELGAMAL");
        testCreateKeyPair(PublicKeyAlgorithmTags.DSA, "DSA");
        testCreateKeyPair(PublicKeyAlgorithmTags.ECDH, "X25519");
        testCreateKeyPair(PublicKeyAlgorithmTags.ECDH, "X448");
        testCreateKeyPair(PublicKeyAlgorithmTags.EDDSA_LEGACY, "Ed448");
        testCreateKeyPair(PublicKeyAlgorithmTags.EDDSA_LEGACY, "Ed25519");
        testCreateKeyPair(PublicKeyAlgorithmTags.ECDSA, "ECDSA");
        testCreateKeyPair(PublicKeyAlgorithmTags.ELGAMAL_GENERAL, "ELGAMAL");
        testCreateKeyPair(PublicKeyAlgorithmTags.X25519, "X25519");
        testCreateKeyPair(PublicKeyAlgorithmTags.X448, "X448");
        testCreateKeyPair(PublicKeyAlgorithmTags.Ed25519, "Ed25519");
        testCreateKeyPair(PublicKeyAlgorithmTags.Ed448, "Ed448");
    }

    private void testCreateKeyPair(int algorithm, String name)
        throws Exception
    {
        testCreateKeyPair(algorithm, algorithm, name);
    }

    private void testCreateKeyPair(int algorithm1, int algorithm2, String name)
        throws Exception
    {
        Date creationDate = new Date();
        KeyPairGenerator gen = KeyPairGenerator.getInstance(name, "BC");
        KeyPair keyPair = gen.generateKeyPair();

        BcPGPKeyConverter converter = new BcPGPKeyConverter();
        PGPKeyPair jcaPgpPair = new JcaPGPKeyPair(algorithm1, keyPair, creationDate);
        AsymmetricKeyParameter publicKey = converter.getPublicKey(jcaPgpPair.getPublicKey());
        AsymmetricKeyParameter privateKey = converter.getPrivateKey(jcaPgpPair.getPrivateKey()); // This line threw previously.
        AsymmetricCipherKeyPair asymKeyPair = new AsymmetricCipherKeyPair(publicKey, privateKey);

        PGPKeyPair bcKeyPair = new BcPGPKeyPair(algorithm2, asymKeyPair, creationDate);

        JcaPGPKeyConverter jcaPGPKeyConverter = new JcaPGPKeyConverter().setProvider(new BouncyCastleProvider());
        PrivateKey privKey = jcaPGPKeyConverter.getPrivateKey(jcaPgpPair.getPrivateKey());
        PublicKey pubKey = jcaPGPKeyConverter.getPublicKey(jcaPgpPair.getPublicKey());

        if (!Arrays.equals(jcaPgpPair.getPrivateKey().getPrivateKeyDataPacket().getEncoded(),
            bcKeyPair.getPrivateKey().getPrivateKeyDataPacket().getEncoded()))
        {
            throw new PGPException("JcaPGPKeyPair and BcPGPKeyPair private keys are not equal.");
        }

        if (algorithm1 == algorithm2 && !Arrays.equals(jcaPgpPair.getPublicKey().getPublicKeyPacket().getEncoded(),
            bcKeyPair.getPublicKey().getPublicKeyPacket().getEncoded()))
        {
            throw new PGPException("JcaPGPKeyPair and BcPGPKeyPair public keys are not equal.");
        }
//        byte[] b1 = privKey.getEncoded();
//        byte[] b2 = keyPair.getPrivate().getEncoded();
//        for (int i = 0; i < b1.length; ++i)
//        {
//            if (b1[i] != b2[i])
//            {
//                System.out.println(i + " " + b1[i] + " " + b2[i]);
//            }
//        }

        isTrue(Arrays.equals(pubKey.getEncoded(), keyPair.getPublic().getEncoded()));
        isTrue(privKey.toString().equals(keyPair.getPrivate().toString()));
        // getEncoded() are Not equal as privKey.hasPublicKey is false but keyPair.getPrivate().hasPublicKey is true
        //isTrue(Arrays.equals(privKey.getEncoded(), keyPair.getPrivate().getEncoded()));
    }

    public void testKeyRings()
        throws Exception
    {
        keyringTest("Ed25519", PublicKeyAlgorithmTags.EDDSA_LEGACY, "X25519", PublicKeyAlgorithmTags.ECDH, HashAlgorithmTags.SHA256, SymmetricKeyAlgorithmTags.AES_128);
        keyringTest("ED25519", PublicKeyAlgorithmTags.Ed25519, "X25519", PublicKeyAlgorithmTags.X25519, HashAlgorithmTags.SHA384, SymmetricKeyAlgorithmTags.AES_128);
        keyringTest("ED25519", PublicKeyAlgorithmTags.Ed25519, "X25519", PublicKeyAlgorithmTags.X25519, HashAlgorithmTags.SHA512, SymmetricKeyAlgorithmTags.AES_128);
        keyringTest("Ed25519", PublicKeyAlgorithmTags.EDDSA_LEGACY, "X25519", PublicKeyAlgorithmTags.ECDH, HashAlgorithmTags.SHA256, SymmetricKeyAlgorithmTags.AES_192);
        keyringTest("Ed25519", PublicKeyAlgorithmTags.EDDSA_LEGACY, "X25519", PublicKeyAlgorithmTags.ECDH, HashAlgorithmTags.SHA256, SymmetricKeyAlgorithmTags.AES_256);
        keyringTest("Ed448", PublicKeyAlgorithmTags.Ed448, "X448", PublicKeyAlgorithmTags.X448, HashAlgorithmTags.SHA256, SymmetricKeyAlgorithmTags.AES_128);
        keyringTest("Ed448", PublicKeyAlgorithmTags.EDDSA_LEGACY, "X448", PublicKeyAlgorithmTags.ECDH, HashAlgorithmTags.SHA256, SymmetricKeyAlgorithmTags.AES_128);
        keyringTest("Ed448", PublicKeyAlgorithmTags.Ed448, "X448", PublicKeyAlgorithmTags.X448, HashAlgorithmTags.SHA384, SymmetricKeyAlgorithmTags.AES_128);
        keyringTest("Ed448", PublicKeyAlgorithmTags.Ed448, "X448", PublicKeyAlgorithmTags.X448, HashAlgorithmTags.SHA512, SymmetricKeyAlgorithmTags.AES_128);
        keyringTest("Ed448", PublicKeyAlgorithmTags.EDDSA_LEGACY, "X448", PublicKeyAlgorithmTags.ECDH, HashAlgorithmTags.SHA256, SymmetricKeyAlgorithmTags.AES_192);
        keyringTest("Ed448", PublicKeyAlgorithmTags.EDDSA_LEGACY, "X448", PublicKeyAlgorithmTags.ECDH, HashAlgorithmTags.SHA256, SymmetricKeyAlgorithmTags.AES_256);
    }

    private void keyringTest(String ed_str, int ed_num, String x_str, int x_num, int hashAlgorithm, int symmetricWrapAlgorithm)
        throws Exception
    {

        String identity = "eric@bouncycastle.org";
        char[] passPhrase = "Hello, world!".toCharArray();

        KeyPairGenerator edKp = KeyPairGenerator.getInstance("EdDSA", "BC");

        edKp.initialize(new ECNamedCurveGenParameterSpec(ed_str));

        PGPKeyPair dsaKeyPair = new JcaPGPKeyPair(ed_num, edKp.generateKeyPair(), new Date());

        KeyPairGenerator dhKp = KeyPairGenerator.getInstance("XDH", "BC");

        dhKp.initialize(new ECNamedCurveGenParameterSpec(x_str));

        PGPKeyPair dhKeyPair = new JcaPGPKeyPair(x_num, new PGPKdfParameters(hashAlgorithm, symmetricWrapAlgorithm),dhKp.generateKeyPair(), new Date());

        encryptDecryptTest(dhKeyPair.getPublicKey(), dhKeyPair.getPrivateKey());
        encryptDecryptBcTest(dhKeyPair.getPublicKey(), dhKeyPair.getPrivateKey());

        PGPDigestCalculator sha1Calc = new JcaPGPDigestCalculatorProviderBuilder().build().get(HashAlgorithmTags.SHA1);

        PGPKeyRingGenerator keyRingGen = new PGPKeyRingGenerator(
            PGPSignature.POSITIVE_CERTIFICATION, dsaKeyPair,
            identity, sha1Calc, null, null,
            new JcaPGPContentSignerBuilder(dsaKeyPair.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA256).setProvider("BC"),
            new JcePBESecretKeyEncryptorBuilder(PGPEncryptedData.AES_256, sha1Calc).setProvider("BC").build(passPhrase));

        keyRingGen.addSubKey(dhKeyPair);

        ByteArrayOutputStream secretOut = new ByteArrayOutputStream();

        PGPSecretKeyRing secRing = keyRingGen.generateSecretKeyRing();

//        PGPPublicKeyRing pubRing = keyRingGen.generatePublicKeyRing();
//
        secRing.encode(secretOut);
//
        secretOut.close();
        secRing = new PGPSecretKeyRing(secretOut.toByteArray(), new JcaKeyFingerprintCalculator());

        Iterator pIt = secRing.getPublicKeys();
        pIt.next();

        PGPPublicKey sKey = (PGPPublicKey)pIt.next();
        PGPPublicKey vKey = secRing.getPublicKey();

        Iterator sIt = sKey.getSignatures();
        int count = 0;
        while (sIt.hasNext())
        {
            PGPSignature sig = (PGPSignature)sIt.next();

            if (sig.getKeyID() == vKey.getKeyID()
                && sig.getSignatureType() == PGPSignature.SUBKEY_BINDING)
            {
                count++;
                sig.init(new JcaPGPContentVerifierBuilderProvider().setProvider("BC"), vKey);

                if (!sig.verifyCertification(vKey, sKey))
                {
                    fail("failed to verify sub-key signature.");
                }
            }
        }

        isTrue(count == 1);

        secRing = new PGPSecretKeyRing(secretOut.toByteArray(), new JcaKeyFingerprintCalculator());
        PGPPublicKey pubKey = null;
        PGPPrivateKey privKey = null;

        for (Iterator it = secRing.getPublicKeys(); it.hasNext(); )
        {
            pubKey = (PGPPublicKey)it.next();
            if (pubKey.isEncryptionKey())
            {
                privKey = secRing.getSecretKey(pubKey.getKeyID()).extractPrivateKey(
                    new JcePBESecretKeyDecryptorBuilder().setProvider(new BouncyCastleProvider()).build(passPhrase));
                break;
            }
        }

        encryptDecryptTest(pubKey, privKey);
        encryptDecryptBcTest(pubKey, privKey);
    }

    private void encryptDecryptBcTest(PGPPublicKey pubKey, PGPPrivateKey secKey)
        throws Exception
    {
        byte[] text = {(byte)'h', (byte)'e', (byte)'l', (byte)'l', (byte)'o', (byte)' ', (byte)'w', (byte)'o', (byte)'r', (byte)'l', (byte)'d', (byte)'!', (byte)'\n'};

        PGPLiteralDataGenerator lData = new PGPLiteralDataGenerator();
        ByteArrayOutputStream ldOut = new ByteArrayOutputStream();
        OutputStream pOut = lData.open(ldOut, PGPLiteralDataGenerator.UTF8, PGPLiteralData.CONSOLE, text.length, new Date());

        pOut.write(text);

        pOut.close();

        byte[] data = ldOut.toByteArray();

        ByteArrayOutputStream cbOut = new ByteArrayOutputStream();

        PGPEncryptedDataGenerator cPk = new PGPEncryptedDataGenerator(new BcPGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.CAST5).setSecureRandom(new SecureRandom()));

        cPk.addMethod(new BcPublicKeyKeyEncryptionMethodGenerator(pubKey));

        OutputStream cOut = cPk.open(new UncloseableOutputStream(cbOut), data.length);

        cOut.write(data);

        cOut.close();

        BcPGPObjectFactory pgpF = new BcPGPObjectFactory(cbOut.toByteArray());

        PGPEncryptedDataList encList = (PGPEncryptedDataList)pgpF.nextObject();

        PGPPublicKeyEncryptedData encP = (PGPPublicKeyEncryptedData)encList.get(0);

        InputStream clear = encP.getDataStream(new BcPublicKeyDataDecryptorFactory(secKey));

        pgpF = new BcPGPObjectFactory(clear);

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

    private void encryptDecryptTest(PGPPublicKey pubKey, PGPPrivateKey secKey)
        throws Exception
    {
        byte[] text = {(byte)'h', (byte)'e', (byte)'l', (byte)'l', (byte)'o', (byte)' ', (byte)'w', (byte)'o', (byte)'r', (byte)'l', (byte)'d', (byte)'!', (byte)'\n'};

        PGPLiteralDataGenerator lData = new PGPLiteralDataGenerator();
        ByteArrayOutputStream ldOut = new ByteArrayOutputStream();
        OutputStream pOut = lData.open(ldOut, PGPLiteralDataGenerator.UTF8, PGPLiteralData.CONSOLE, text.length, new Date());

        pOut.write(text);

        pOut.close();

        byte[] data = ldOut.toByteArray();

        ByteArrayOutputStream cbOut = new ByteArrayOutputStream();

        PGPEncryptedDataGenerator cPk = new PGPEncryptedDataGenerator(new JcePGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.CAST5).setProvider("BC").setSecureRandom(new SecureRandom()));

        cPk.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(pubKey).setProvider(new BouncyCastleProvider()).setSecureRandom(CryptoServicesRegistrar.getSecureRandom()));

        OutputStream cOut = cPk.open(new UncloseableOutputStream(cbOut), data.length);

        cOut.write(data);

        cOut.close();

        JcaPGPObjectFactory pgpF = new JcaPGPObjectFactory(cbOut.toByteArray());

        PGPEncryptedDataList encList = (PGPEncryptedDataList)pgpF.nextObject();

        PGPPublicKeyEncryptedData encP = (PGPPublicKeyEncryptedData)encList.get(0);

        InputStream clear = encP.getDataStream(new JcePublicKeyDataDecryptorFactoryBuilder().setProvider(new BouncyCastleProvider()).build(secKey));

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
}
