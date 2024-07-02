package org.bouncycastle.openpgp.test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Date;
import java.util.Iterator;

import org.bouncycastle.bcpg.AEADAlgorithmTags;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyPacket;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.Wrapper;
import org.bouncycastle.crypto.agreement.X25519Agreement;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.RFC3394WrapEngine;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.HKDFParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;
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
import org.bouncycastle.openpgp.operator.PGPContentVerifier;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.PGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
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
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;
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
        testX25519HKDF();
        testKeyRings();
        testBcPGPKeyPair();
//        testBcPGPDataEncryptorBuilder();
        testBcPGPContentVerifierBuilderProvider();
        //testBcPBESecretKeyDecryptorBuilder();
        testBcKeyFingerprintCalculator();
        testBcStandardDigests();
    }

    private void testBcStandardDigests()
        throws Exception
    {
        PGPDigestCalculatorProvider digCalcBldr = new BcPGPDigestCalculatorProvider();

        testDigestCalc(digCalcBldr.get(HashAlgorithmTags.MD5), Hex.decode("900150983cd24fb0d6963f7d28e17f72"));
        testDigestCalc(digCalcBldr.get(HashAlgorithmTags.SHA1), Hex.decode("a9993e364706816aba3e25717850c26c9cd0d89d"));
        testDigestCalc(digCalcBldr.get(HashAlgorithmTags.RIPEMD160), Hex.decode("8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"));
        testDigestCalc(digCalcBldr.get(HashAlgorithmTags.SHA256), Hex.decode("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
        testDigestCalc(digCalcBldr.get(HashAlgorithmTags.SHA384), Hex.decode("cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"));
        testDigestCalc(digCalcBldr.get(HashAlgorithmTags.SHA512), Hex.decode("ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"));
        testDigestCalc(digCalcBldr.get(HashAlgorithmTags.SHA224), Hex.decode("23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7"));
        testDigestCalc(digCalcBldr.get(HashAlgorithmTags.SHA3_256), Hex.decode("3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"));
        testDigestCalc(digCalcBldr.get(HashAlgorithmTags.SHA3_512), Hex.decode("b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0"));
    }

    private void testDigestCalc(PGPDigestCalculator digCalc, byte[] expected)
        throws IOException
    {
        OutputStream dOut = digCalc.getOutputStream();

        dOut.write(Strings.toByteArray("abc"));

        dOut.close();

        byte[] res = digCalc.getDigest();

        isTrue(Arrays.areEqual(res, expected));
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
        testException("Unsupported PGP key version: ", "UnsupportedPacketVersionException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                calculator.calculateFingerprint(pubKeyPacket2);
            }
        });
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
        testException("null cipher specified", "IllegalArgumentException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                new BcPGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.NULL);
            }
        });

        testException("AEAD algorithms can only be used with AES", "IllegalStateException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                new BcPGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.IDEA).setWithAEAD(AEADAlgorithmTags.OCB, 6);
            }
        });

        testException("minimum chunkSize is 6", "IllegalArgumentException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                new BcPGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.AES_256).setWithAEAD(AEADAlgorithmTags.OCB, 5);
            }
        });

        testException("invalid parameters:", "PGPException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                new BcPGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.AES_256).build(new byte[0]);
            }
        });

        isTrue(new BcPGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.AES_256).setWithIntegrityPacket(false).build(new byte[32]).getIntegrityCalculator() == null);

        isEquals(16, new BcPGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.AES_256).setWithAEAD(AEADAlgorithmTags.OCB, 6).build(new byte[32]).getBlockSize());
    }

    public void testBcPGPKeyPair()
        throws Exception
    {
        testCreateKeyPairDefault(PublicKeyAlgorithmTags.X448, "X448");
        testCreateKeyPairDefault(PublicKeyAlgorithmTags.X25519, "X25519");
        testCreateKeyPairDefault(PublicKeyAlgorithmTags.EDDSA_LEGACY, PublicKeyAlgorithmTags.Ed25519, "Ed25519");
        testCreateKeyPairDefault(PublicKeyAlgorithmTags.Ed448, "Ed448");
        testCreateKeyPairDefault(PublicKeyAlgorithmTags.ECDH, PublicKeyAlgorithmTags.X25519, "X25519");
        testCreateKeyPairEC(PublicKeyAlgorithmTags.ECDH, "ECDH", "P-256");
        testCreateKeyPairEC(PublicKeyAlgorithmTags.ECDH, "ECDH", "P-384");
        testCreateKeyPairEC(PublicKeyAlgorithmTags.ECDH, "ECDH", "P-521");
        testCreateKeyPairEC(PublicKeyAlgorithmTags.ECDH, "ECDH", "brainpoolP256r1");
        testCreateKeyPairEC(PublicKeyAlgorithmTags.ECDH, "ECDH", "brainpoolP384r1");
        testCreateKeyPairEC(PublicKeyAlgorithmTags.ECDH, "ECDH", "brainpoolP512r1");
        testCreateKeyPairDefault(PublicKeyAlgorithmTags.X25519, PublicKeyAlgorithmTags.ECDH, "X25519");
        testCreateKeyPairDefault(PublicKeyAlgorithmTags.Ed25519, PublicKeyAlgorithmTags.EDDSA_LEGACY, "Ed25519");
        testCreateKeyPairDefault(PublicKeyAlgorithmTags.RSA_GENERAL, "RSA");
        testCreateKeyPairDefault(PublicKeyAlgorithmTags.ELGAMAL_GENERAL, "ELGAMAL");
        testCreateKeyPairDefault(PublicKeyAlgorithmTags.DSA, "DSA");
        testCreateKeyPairDefault(PublicKeyAlgorithmTags.ECDH, "X25519");
        testCreateKeyPairDefault(PublicKeyAlgorithmTags.EDDSA_LEGACY, "Ed25519");
        testCreateKeyPairDefault(PublicKeyAlgorithmTags.ECDSA, "ECDSA");
        testCreateKeyPairEC(PublicKeyAlgorithmTags.ECDSA, "ECDSA", "P-256");
        testCreateKeyPairEC(PublicKeyAlgorithmTags.ECDSA, "ECDSA", "P-384");
        testCreateKeyPairEC(PublicKeyAlgorithmTags.ECDSA, "ECDSA", "P-521");
        testCreateKeyPairEC(PublicKeyAlgorithmTags.ECDSA, "ECDSA", "brainpoolP256r1");
        testCreateKeyPairEC(PublicKeyAlgorithmTags.ECDSA, "ECDSA", "brainpoolP384r1");
        testCreateKeyPairEC(PublicKeyAlgorithmTags.ECDSA, "ECDSA", "brainpoolP512r1");
        testCreateKeyPairDefault(PublicKeyAlgorithmTags.ELGAMAL_GENERAL, "ELGAMAL");
        testCreateKeyPairDefault(PublicKeyAlgorithmTags.Ed25519, "Ed25519");
    }

    private void testCreateKeyPairDefault(int algorithm, String name)
        throws Exception
    {
        testCreateKeyPair(algorithm, name, new KeyPairGeneratorOperation()
        {
            @Override
            public void initialize(KeyPairGenerator gen)
                throws Exception
            {
            }
        });
    }

    private void testCreateKeyPairDefault(int algorithm1, int algorithm2, String name)
        throws Exception
    {
        testCreateKeyPair(algorithm1, algorithm2, name, new KeyPairGeneratorOperation()
        {
            @Override
            public void initialize(KeyPairGenerator gen)
                throws Exception
            {
            }
        });
    }
    
    private void testCreateKeyPairEC(int algorithm, String name, final String curveName)
        throws Exception
    {
        testCreateKeyPair(algorithm, name, new KeyPairGeneratorOperation()
        {
            @Override
            public void initialize(KeyPairGenerator gen)
                throws Exception
            {
                gen.initialize(new ECNamedCurveGenParameterSpec(curveName));
            }
        });
    }

    private void testCreateKeyPair(int algorithm, String name, KeyPairGeneratorOperation kpgen)
        throws Exception
    {
        testCreateKeyPair(algorithm, algorithm, name, kpgen);
    }

    private interface KeyPairGeneratorOperation
    {
        void initialize(KeyPairGenerator gen)
            throws Exception;
    }

    private void testCreateKeyPair(int algorithm1, int algorithm2, String name, KeyPairGeneratorOperation kpgen)
        throws Exception
    {
        Date creationDate = new Date();
        KeyPairGenerator gen = KeyPairGenerator.getInstance(name, "BC");
        kpgen.initialize(gen);
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

        if (algorithm1 == algorithm2 && !Arrays.areEqual(jcaPgpPair.getPrivateKey().getPrivateKeyDataPacket().getEncoded(),
            bcKeyPair.getPrivateKey().getPrivateKeyDataPacket().getEncoded()))
        {
            throw new PGPException("JcaPGPKeyPair and BcPGPKeyPair private keys are not equal.");
        }

        if (algorithm1 == algorithm2 && !Arrays.areEqual(jcaPgpPair.getPublicKey().getPublicKeyPacket().getEncoded(),
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

        isTrue("pub key mismatch: " + name, Arrays.areEqual(pubKey.getEncoded(), keyPair.getPublic().getEncoded()));
        isTrue(privKey.toString().equals(keyPair.getPrivate().toString()));
        // getEncoded() are Not equal as privKey.hasPublicKey is false but keyPair.getPrivate().hasPublicKey is true
        //isTrue(Arrays.equals(privKey.getEncoded(), keyPair.getPrivate().getEncoded()));
    }

    public void testKeyRings()
        throws Exception
    {
        keyringTest("EdDSA", "Ed448", PublicKeyAlgorithmTags.Ed448, "XDH", "X448", PublicKeyAlgorithmTags.X448, HashAlgorithmTags.SHA512, SymmetricKeyAlgorithmTags.AES_256);
        keyringTest("EdDSA", "Ed25519", PublicKeyAlgorithmTags.EDDSA_LEGACY, "XDH", "X25519", PublicKeyAlgorithmTags.ECDH, HashAlgorithmTags.SHA256, SymmetricKeyAlgorithmTags.AES_128);


        keyringTest("EdDSA", "ED25519", PublicKeyAlgorithmTags.Ed25519, "XDH", "X25519", PublicKeyAlgorithmTags.X25519, HashAlgorithmTags.SHA256, SymmetricKeyAlgorithmTags.AES_128);


        keyringTest("ECDSA", "NIST P-256", PublicKeyAlgorithmTags.ECDSA, "ECDH", "NIST P-256", PublicKeyAlgorithmTags.ECDH, HashAlgorithmTags.SHA256, SymmetricKeyAlgorithmTags.AES_128);
        keyringTest("ECDSA", "NIST P-384", PublicKeyAlgorithmTags.ECDSA, "ECDH", "NIST P-384", PublicKeyAlgorithmTags.ECDH, HashAlgorithmTags.SHA384, SymmetricKeyAlgorithmTags.AES_192);
        keyringTest("ECDSA", "NIST P-521", PublicKeyAlgorithmTags.ECDSA, "ECDH", "NIST P-521", PublicKeyAlgorithmTags.ECDH, HashAlgorithmTags.SHA512, SymmetricKeyAlgorithmTags.AES_256);
        keyringTest("ECDSA", "brainpoolP256r1", PublicKeyAlgorithmTags.ECDSA, "ECDH", "brainpoolP256r1", PublicKeyAlgorithmTags.ECDH, HashAlgorithmTags.SHA256, SymmetricKeyAlgorithmTags.AES_128);
        keyringTest("ECDSA", "brainpoolP384r1", PublicKeyAlgorithmTags.ECDSA, "ECDH", "brainpoolP384r1", PublicKeyAlgorithmTags.ECDH, HashAlgorithmTags.SHA384, SymmetricKeyAlgorithmTags.AES_192);
        keyringTest("ECDSA", "brainpoolP512r1", PublicKeyAlgorithmTags.ECDSA, "ECDH", "brainpoolP512r1", PublicKeyAlgorithmTags.ECDH, HashAlgorithmTags.SHA512, SymmetricKeyAlgorithmTags.AES_256);

        keyringTest("EdDSA", "ED25519", PublicKeyAlgorithmTags.EDDSA_LEGACY, "XDH", "X25519", PublicKeyAlgorithmTags.ECDH, HashAlgorithmTags.SHA384, SymmetricKeyAlgorithmTags.AES_128);
        keyringTest("EdDSA", "ED25519", PublicKeyAlgorithmTags.EDDSA_LEGACY, "XDH", "X25519", PublicKeyAlgorithmTags.ECDH, HashAlgorithmTags.SHA512, SymmetricKeyAlgorithmTags.AES_128);
        keyringTest("EdDSA", "Ed25519", PublicKeyAlgorithmTags.EDDSA_LEGACY, "XDH", "X25519", PublicKeyAlgorithmTags.ECDH, HashAlgorithmTags.SHA256, SymmetricKeyAlgorithmTags.AES_192);
        keyringTest("EdDSA", "Ed25519", PublicKeyAlgorithmTags.EDDSA_LEGACY, "XDH", "X25519", PublicKeyAlgorithmTags.ECDH, HashAlgorithmTags.SHA256, SymmetricKeyAlgorithmTags.AES_256);
        keyringTest("EdDSA", "Ed25519", PublicKeyAlgorithmTags.EDDSA_LEGACY, "XDH", "X25519", PublicKeyAlgorithmTags.ECDH, HashAlgorithmTags.SHA256, SymmetricKeyAlgorithmTags.CAMELLIA_128);
        keyringTest("EdDSA", "Ed25519", PublicKeyAlgorithmTags.EDDSA_LEGACY, "XDH", "X25519", PublicKeyAlgorithmTags.ECDH, HashAlgorithmTags.SHA256, SymmetricKeyAlgorithmTags.CAMELLIA_192);
        keyringTest("EdDSA", "Ed25519", PublicKeyAlgorithmTags.EDDSA_LEGACY, "XDH", "X25519", PublicKeyAlgorithmTags.ECDH, HashAlgorithmTags.SHA256, SymmetricKeyAlgorithmTags.CAMELLIA_256);
    }

    private void keyringTest(String algorithmName1, String ed_str, int ed_num, String algorithmName2, String x_str, int x_num, int hashAlgorithm, int symmetricWrapAlgorithm)
        throws Exception
    {

        String identity = "eric@bouncycastle.org";
        char[] passPhrase = "Hello, world!".toCharArray();

        KeyPairGenerator edKp = KeyPairGenerator.getInstance(algorithmName1, "BC");

        edKp.initialize(new ECNamedCurveGenParameterSpec(ed_str));

        PGPKeyPair dsaKeyPair = new JcaPGPKeyPair(ed_num, edKp.generateKeyPair(), new Date());

        KeyPairGenerator dhKp = KeyPairGenerator.getInstance(algorithmName2, "BC");

        dhKp.initialize(new ECNamedCurveGenParameterSpec(x_str));

        PGPKeyPair dhKeyPair = new JcaPGPKeyPair(x_num, new PGPKdfParameters(hashAlgorithm, symmetricWrapAlgorithm), dhKp.generateKeyPair(), new Date());

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
                   // TODO: appears to be failing on CI system
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

        InputStream clear = encP.getDataStream(new JcePublicKeyDataDecryptorFactoryBuilder().setProvider(new BouncyCastleProvider()).setContentProvider(new BouncyCastleProvider()).build(secKey));

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

    public void testX25519HKDF()
        throws Exception
    {
        byte[] ephmeralKey = Hex.decode("87cf18d5f1b53f817cce5a004cf393cc8958bddc065f25f84af509b17dd36764");
        byte[] ephmeralSecretKey = Hex.decode("af1e43c0d123efe893a7d4d390f3a761e3fac33dfc7f3edaa830c9011352c779");
        byte[] publicKey = Hex.decode("8693248367f9e5015db922f8f48095dda784987f2d5985b12fbad16caf5e4435");
        byte[] expectedHKDF = Hex.decode("f66dadcff64592239b254539b64ff607");
        byte[] keyEnc = Hex.decode("dea355437956617901e06957fbca8a6a47a5b5153e8d3ab7");
        byte[] expectedDecryptedSessionKey = Hex.decode("dd708f6fa1ed65114d68d2343e7c2f1d");
        X25519PrivateKeyParameters ephmeralprivateKeyParameters = new X25519PrivateKeyParameters(ephmeralSecretKey);
        X25519PublicKeyParameters publicKeyParameters = new X25519PublicKeyParameters(publicKey);
        X25519Agreement agreement = new X25519Agreement();
        agreement.init(ephmeralprivateKeyParameters);
        byte[] secret = new byte[agreement.getAgreementSize()];
        agreement.calculateAgreement(publicKeyParameters, secret, 0);
        byte[] output2 = new byte[16];
        HKDFBytesGenerator hkdf = new HKDFBytesGenerator(new SHA256Digest());
        hkdf.init(new HKDFParameters(Arrays.concatenate(ephmeralKey, publicKey, secret), null, "OpenPGP X25519".getBytes()));
        hkdf.generateBytes(output2, 0, 16);

        isTrue(Arrays.areEqual(output2, expectedHKDF));
        Wrapper c = new RFC3394WrapEngine(AESEngine.newInstance());
        c.init(false, new KeyParameter(output2));
        byte[] output = c.unwrap(keyEnc, 0, keyEnc.length);
        isTrue(Arrays.areEqual(output, expectedDecryptedSessionKey));
    }



}
