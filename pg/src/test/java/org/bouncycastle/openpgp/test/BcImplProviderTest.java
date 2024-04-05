package org.bouncycastle.openpgp.test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Date;
import java.util.Iterator;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.bcpg.BCPGKey;
import org.bouncycastle.bcpg.DSASecretBCPGKey;
import org.bouncycastle.bcpg.ECSecretBCPGKey;
import org.bouncycastle.bcpg.Ed25519SecretBCPGKey;
import org.bouncycastle.bcpg.Ed448SecretBCPGKey;
import org.bouncycastle.bcpg.EdSecretBCPGKey;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.RSASecretBCPGKey;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.digests.MD2Digest;
import org.bouncycastle.crypto.digests.MD5Digest;
import org.bouncycastle.crypto.digests.RIPEMD160Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA224Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.digests.SHA3Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.digests.TigerDigest;
import org.bouncycastle.crypto.generators.X25519KeyPairGenerator;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.params.X25519KeyGenerationParameters;
import org.bouncycastle.crypto.signers.DSADigestSigner;
import org.bouncycastle.crypto.signers.DSASigner;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.signers.Ed25519Signer;
import org.bouncycastle.crypto.signers.Ed448Signer;
import org.bouncycastle.crypto.signers.RSADigestSigner;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveGenParameterSpec;
import org.bouncycastle.jce.spec.ElGamalParameterSpec;
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
import org.bouncycastle.openpgp.operator.PGPContentSigner;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.bc.BcPGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.bc.BcPGPKeyConverter;
import org.bouncycastle.openpgp.operator.bc.BcPGPKeyPair;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyKeyEncryptionMethodGenerator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyConverter;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyEncryptorBuilder;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.test.FixedSecureRandom;
import org.bouncycastle.util.test.SimpleTest;
import org.bouncycastle.util.test.UncloseableOutputStream;

public class BcImplProviderTest
    extends SimpleTest
{
    @Override
    public String getName()
    {
        return "BcImplProviderTest";
    }

    @Override
    public void performTest()
        throws Exception
    {
        testBcImplProvider();
    }

    public void testBcImplProvider()
        throws Exception
    {
        //createDigest
        final BcPGPDigestCalculatorProvider provider = new BcPGPDigestCalculatorProvider();
        testCreateDigest(provider, HashAlgorithmTags.SHA1, new SHA1Digest());
        testCreateDigest(provider, HashAlgorithmTags.SHA224, new SHA224Digest());
        testCreateDigest(provider, HashAlgorithmTags.SHA256, new SHA256Digest());
        testCreateDigest(provider, HashAlgorithmTags.SHA384, new SHA384Digest());
        testCreateDigest(provider, HashAlgorithmTags.SHA512, new SHA512Digest());
        testCreateDigest(provider, HashAlgorithmTags.SHA3_224, new SHA3Digest(224));
        testCreateDigest(provider, HashAlgorithmTags.SHA3_256, new SHA3Digest(256));
        testCreateDigest(provider, HashAlgorithmTags.SHA3_384, new SHA3Digest(384));
        testCreateDigest(provider, HashAlgorithmTags.SHA3_512, new SHA3Digest(512));
        testCreateDigest(provider, HashAlgorithmTags.MD2, new MD2Digest());
        testCreateDigest(provider, HashAlgorithmTags.MD5, new MD5Digest());
        testCreateDigest(provider, HashAlgorithmTags.RIPEMD160, new RIPEMD160Digest());
        testCreateDigest(provider, HashAlgorithmTags.TIGER_192, new TigerDigest());
        testException("cannot recognise digest", "PGPException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                provider.get(HashAlgorithmTags.SM3);
            }
        });

        //createSigner
        testCreateSigner(PublicKeyAlgorithmTags.DSA, new DSADigestSigner(new DSASigner(), new SHA1Digest()), "DSA",
            new PrivateKeyOperation()
            {
                @Override
                public BCPGKey getPrivateBCPGKey(PGPPublicKey pub, PrivateKey privKey)
                    throws IOException
                {
                    return new DSASecretBCPGKey(((DSAPrivateKey)privKey).getX());
                }
            },
            new KeyPairGeneratorOperation()
            {
                @Override
                public void initialize(KeyPairGenerator kpGen)
                    throws InvalidAlgorithmParameterException
                {
                    kpGen.initialize(1024);
                }
            });
        testCreateSigner(PublicKeyAlgorithmTags.RSA_GENERAL, new RSADigestSigner(new SHA1Digest()), "RSA",
            new PrivateKeyOperation()
            {
                @Override
                public BCPGKey getPrivateBCPGKey(PGPPublicKey pub, PrivateKey privKey)
                    throws IOException
                {
                    RSAPrivateCrtKey rsK = (RSAPrivateCrtKey)privKey;
                    return new RSASecretBCPGKey(rsK.getPrivateExponent(), rsK.getPrimeP(), rsK.getPrimeQ());
                }
            },
            new KeyPairGeneratorOperation()
            {
                @Override
                public void initialize(KeyPairGenerator kpGen)
                    throws InvalidAlgorithmParameterException
                {
                    kpGen.initialize(1024);
                }
            });
        testCreateSigner(PublicKeyAlgorithmTags.ECDSA, new DSADigestSigner(new ECDSASigner(), new SHA1Digest()), "ECDSA",
            new PrivateKeyOperation()
            {
                @Override
                public BCPGKey getPrivateBCPGKey(PGPPublicKey pub, PrivateKey privKey)
                    throws IOException
                {
                    return new ECSecretBCPGKey(((ECPrivateKey)privKey).getS());
                }
            },
            new KeyPairGeneratorOperation()
            {
                @Override
                public void initialize(KeyPairGenerator kpGen)
                    throws InvalidAlgorithmParameterException
                {
                    kpGen.initialize(new ECGenParameterSpec("P-256"));
                }
            });
        testCreateSigner(PublicKeyAlgorithmTags.ECDSA, new DSADigestSigner(new ECDSASigner(), new SHA1Digest()), "ECDSA",
            new PrivateKeyOperation()
            {
                @Override
                public BCPGKey getPrivateBCPGKey(PGPPublicKey pub, PrivateKey privKey)
                    throws IOException
                {
                    return new ECSecretBCPGKey(((ECPrivateKey)privKey).getS());
                }
            },
            new KeyPairGeneratorOperation()
            {
                @Override
                public void initialize(KeyPairGenerator kpGen)
                    throws InvalidAlgorithmParameterException
                {
                    kpGen.initialize(new ECGenParameterSpec("P-384"));
                }
            });
        testCreateSigner(PublicKeyAlgorithmTags.ECDSA, new DSADigestSigner(new ECDSASigner(), new SHA1Digest()), "ECDSA",
            new PrivateKeyOperation()
            {
                @Override
                public BCPGKey getPrivateBCPGKey(PGPPublicKey pub, PrivateKey privKey)
                    throws IOException
                {
                    return new ECSecretBCPGKey(((ECPrivateKey)privKey).getS());
                }
            },
            new KeyPairGeneratorOperation()
            {
                @Override
                public void initialize(KeyPairGenerator kpGen)
                    throws InvalidAlgorithmParameterException
                {
                    kpGen.initialize(new ECGenParameterSpec("P-521"));
                }
            });
        testCreateSigner(PublicKeyAlgorithmTags.ECDSA, new DSADigestSigner(new ECDSASigner(), new SHA1Digest()), "ECDSA",
            new PrivateKeyOperation()
            {
                @Override
                public BCPGKey getPrivateBCPGKey(PGPPublicKey pub, PrivateKey privKey)
                    throws IOException
                {
                    return new ECSecretBCPGKey(((ECPrivateKey)privKey).getS());
                }
            },
            new KeyPairGeneratorOperation()
            {
                @Override
                public void initialize(KeyPairGenerator kpGen)
                    throws InvalidAlgorithmParameterException
                {
                    kpGen.initialize(new ECGenParameterSpec("brainpoolP256r1"));
                }
            });
        testCreateSigner(PublicKeyAlgorithmTags.ECDSA, new DSADigestSigner(new ECDSASigner(), new SHA1Digest()), "ECDSA",
            new PrivateKeyOperation()
            {
                @Override
                public BCPGKey getPrivateBCPGKey(PGPPublicKey pub, PrivateKey privKey)
                    throws IOException
                {
                    return new ECSecretBCPGKey(((ECPrivateKey)privKey).getS());
                }
            },
            new KeyPairGeneratorOperation()
            {
                @Override
                public void initialize(KeyPairGenerator kpGen)
                    throws InvalidAlgorithmParameterException
                {
                    kpGen.initialize(new ECGenParameterSpec("brainpoolP384r1"));
                }
            });
        testCreateSigner(PublicKeyAlgorithmTags.ECDSA, new DSADigestSigner(new ECDSASigner(), new SHA1Digest()), "ECDSA",
            new PrivateKeyOperation()
            {
                @Override
                public BCPGKey getPrivateBCPGKey(PGPPublicKey pub, PrivateKey privKey)
                    throws IOException
                {
                    return new ECSecretBCPGKey(((ECPrivateKey)privKey).getS());
                }
            },
            new KeyPairGeneratorOperation()
            {
                @Override
                public void initialize(KeyPairGenerator kpGen)
                    throws InvalidAlgorithmParameterException
                {
                    kpGen.initialize(new ECGenParameterSpec("brainpoolP512r1"));
                }
            });

        testCreateSigner(PublicKeyAlgorithmTags.EDDSA_LEGACY, new EdDsaSigner(new Ed25519Signer(), new SHA1Digest()), "EdDSA",
            new PrivateKeyOperation()
            {
                @Override
                public BCPGKey getPrivateBCPGKey(PGPPublicKey pub, PrivateKey privKey)
                    throws IOException
                {
                    PrivateKeyInfo pInfo = PrivateKeyInfo.getInstance(privKey.getEncoded());
                    return new EdSecretBCPGKey(
                        new BigInteger(1, ASN1OctetString.getInstance(pInfo.parsePrivateKey()).getOctets()));
                }
            },
            new KeyPairGeneratorOperation()
            {
                @Override
                public void initialize(KeyPairGenerator kpGen)
                    throws InvalidAlgorithmParameterException
                {
                    kpGen.initialize(new ECNamedCurveGenParameterSpec("Ed25519"));
                }
            });
        testCreateSigner(PublicKeyAlgorithmTags.Ed448, new EdDsaSigner(new Ed448Signer(new byte[0]), new SHA1Digest()), "EdDSA",
            new PrivateKeyOperation()
            {
                @Override
                public BCPGKey getPrivateBCPGKey(PGPPublicKey pub, PrivateKey privKey)
                    throws IOException
                {
                    PrivateKeyInfo pInfo = PrivateKeyInfo.getInstance(privKey.getEncoded());
                    return new Ed448SecretBCPGKey(ASN1OctetString.getInstance(pInfo.parsePrivateKey()).getOctets());
                }
            },
            new KeyPairGeneratorOperation()
            {
                @Override
                public void initialize(KeyPairGenerator kpGen)
                    throws InvalidAlgorithmParameterException
                {
                    kpGen.initialize(new ECNamedCurveGenParameterSpec("Ed448"));
                }
            });
        testCreateSigner(PublicKeyAlgorithmTags.Ed25519, new EdDsaSigner(new Ed25519Signer(), new SHA1Digest()), "EdDSA",
            new PrivateKeyOperation()
            {
                @Override
                public BCPGKey getPrivateBCPGKey(PGPPublicKey pub, PrivateKey privKey)
                    throws IOException
                {
                    PrivateKeyInfo pInfo = PrivateKeyInfo.getInstance(privKey.getEncoded());
                    return new Ed25519SecretBCPGKey(ASN1OctetString.getInstance(pInfo.parsePrivateKey()).getOctets());
                }
            },
            new KeyPairGeneratorOperation()
            {
                @Override
                public void initialize(KeyPairGenerator kpGen)
                    throws InvalidAlgorithmParameterException
                {
                    kpGen.initialize(new ECNamedCurveGenParameterSpec("Ed25519"));
                }
            });
        testException("cannot recognise keyAlgorithm:", "PGPException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                new BcPGPContentVerifierBuilderProvider().get(PublicKeyAlgorithmTags.X448, HashAlgorithmTags.SHA1)
                    .build(((PGPPublicKeyRing)new JcaPGPObjectFactory(BcPGPDSAElGamalTest.testPubKeyRing).nextObject()).getPublicKey());
            }
        });


//        testException("cannot recognise keyAlgorithm: ", "PGPException", ()->
//        {
//            KeyPairGenerator kpGen = KeyPairGenerator.getInstance("X448", "BC");
//            KeyPair kp = kpGen.generateKeyPair();
//
//            JcaPGPKeyConverter converter = new JcaPGPKeyConverter().setProvider(new BouncyCastleProvider());
//            PGPPublicKey pubKey = converter.getPGPPublicKey(PublicKeyAlgorithmTags.X448, kp.getPublic(), new Date());
//            PGPPrivateKey privKey = new PGPPrivateKey(pubKey.getKeyID(), pubKey.getPublicKeyPacket(), operation.getPrivateBCPGKey(pubKey, kp.getPrivate()));
//        });
        // createBlockCipher
        createBlockCipherTest(SymmetricKeyAlgorithmTags.AES_128);
        createBlockCipherTest(SymmetricKeyAlgorithmTags.AES_192);
        createBlockCipherTest(SymmetricKeyAlgorithmTags.AES_256);
        createBlockCipherTest(SymmetricKeyAlgorithmTags.CAMELLIA_128);
        createBlockCipherTest(SymmetricKeyAlgorithmTags.CAMELLIA_192);
        createBlockCipherTest(SymmetricKeyAlgorithmTags.CAMELLIA_256);
        createBlockCipherTest(SymmetricKeyAlgorithmTags.BLOWFISH);
        createBlockCipherTest(SymmetricKeyAlgorithmTags.CAST5);
        createBlockCipherTest(SymmetricKeyAlgorithmTags.DES);
        createBlockCipherTest(SymmetricKeyAlgorithmTags.IDEA);
        createBlockCipherTest(SymmetricKeyAlgorithmTags.TWOFISH);
        createBlockCipherTest(SymmetricKeyAlgorithmTags.TRIPLE_DES);
        testException("cannot create cipher", "PGPException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                createBlockCipherTest(SymmetricKeyAlgorithmTags.SAFER);
            }
        });

        final PBESecretKeyDecryptor decryptor = new BcPBESecretKeyDecryptorBuilder(new BcPGPDigestCalculatorProvider()).build(BcPGPDSAElGamalTest.pass);
        testException("cannot recognise cipher", "PGPException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                decryptor.recoverKeyData(SymmetricKeyAlgorithmTags.NULL, new byte[32], new byte[12], new byte[16], 0, 16);
            }
        });

        createWrapperTest(SymmetricKeyAlgorithmTags.AES_128);
        createWrapperTest(SymmetricKeyAlgorithmTags.AES_192);
        createWrapperTest(SymmetricKeyAlgorithmTags.AES_256);
        createWrapperTest(SymmetricKeyAlgorithmTags.CAMELLIA_128);
        createWrapperTest(SymmetricKeyAlgorithmTags.CAMELLIA_192);
        createWrapperTest(SymmetricKeyAlgorithmTags.CAMELLIA_256);
        //testException("unknown wrap algorithm: ", "PGPException", ()-> createWrapperTest(SymmetricKeyAlgorithmTags.BLOWFISH));
    }

    private void testCreateDigest(BcPGPDigestCalculatorProvider provider, int algorithm, Digest digest)
        throws PGPException
    {
        PGPDigestCalculator calculator = provider.get(algorithm);
        isEquals(calculator.getAlgorithm(), algorithm);
        byte[] d = new byte[digest.getDigestSize()];
        digest.doFinal(d, 0);
        isTrue(Arrays.areEqual(d, calculator.getDigest()));
        calculator.reset();
    }

    @FunctionalInterface
    interface PrivateKeyOperation
    {
        BCPGKey getPrivateBCPGKey(PGPPublicKey pub, PrivateKey privKey)
            throws IOException;
    }

    @FunctionalInterface
    interface KeyPairGeneratorOperation
    {
        void initialize(KeyPairGenerator kpGen)
            throws InvalidAlgorithmParameterException;
    }


    private void testCreateSigner(int keyAlgorithm, Signer signer, String name, PrivateKeyOperation operation, KeyPairGeneratorOperation kpgOperation)
        throws Exception
    {
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance(name, "BC");
        kpgOperation.initialize(kpGen);
        KeyPair kp = kpGen.generateKeyPair();

        JcaPGPKeyConverter converter = new JcaPGPKeyConverter().setProvider(new BouncyCastleProvider());
        PGPPublicKey pubKey = converter.getPGPPublicKey(keyAlgorithm, kp.getPublic(), new Date());
        PGPPrivateKey privKey = new PGPPrivateKey(pubKey.getKeyID(), pubKey.getPublicKeyPacket(), operation.getPrivateBCPGKey(pubKey, kp.getPrivate()));

        byte[] source = new byte[1024];
        SecureRandom r1 = new SecureRandom();
        r1.nextBytes(source);
        SecureRandom random = new FixedSecureRandom(source);

        final BcPGPContentSignerBuilder builder = new BcPGPContentSignerBuilder(keyAlgorithm, HashAlgorithmTags.SHA1).setSecureRandom(random);
        PGPContentSigner contentSigner = builder.build(PGPSignature.BINARY_DOCUMENT, privKey);

        BcPGPKeyConverter keyConverter = new BcPGPKeyConverter();
        AsymmetricKeyParameter privKeyParam = keyConverter.getPrivateKey(privKey);
        signer.init(true, new ParametersWithRandom(privKeyParam, new FixedSecureRandom(source)));
        isTrue(contentSigner.getKeyAlgorithm() == keyAlgorithm);
        isTrue(areEqual(contentSigner.getSignature(), signer.generateSignature()));
    }

    public void createBlockCipherTest(int tag)
        throws Exception
    {
        char[] passPhrase = "hello".toCharArray();
        KeyPairGenerator dsaKpg = KeyPairGenerator.getInstance("DSA", "BC");

        dsaKpg.initialize(512);

        //
        // this takes a while as the key generator has to generate some DSA params
        // before it generates the key.
        //
        KeyPair dsaKp = dsaKpg.generateKeyPair();

        KeyPairGenerator elgKpg = KeyPairGenerator.getInstance("ELGAMAL", "BC");
        BigInteger g = new BigInteger("153d5d6172adb43045b68ae8e1de1070b6137005686d29d3d73a7749199681ee5b212c9b96bfdcfa5b20cd5e3fd2044895d609cf9b410b7a0f12ca1cb9a428cc", 16);
        BigInteger p = new BigInteger("9494fec095f3b85ee286542b3836fc81a5dd0a0349b4c239dd38744d488cf8e31db8bcb7d33b41abb9e5a33cca9144b1cef332c94bf0573bf047a3aca98cdf3b", 16);

        ElGamalParameterSpec elParams = new ElGamalParameterSpec(p, g);

        elgKpg.initialize(elParams);

        //
        // this is quicker because we are using pregenerated parameters.
        //
        KeyPair elgKp = elgKpg.generateKeyPair();
        PGPKeyPair dsaKeyPair = new JcaPGPKeyPair(PGPPublicKey.DSA, dsaKp, new Date());
        PGPKeyPair elgKeyPair = new JcaPGPKeyPair(PGPPublicKey.ELGAMAL_ENCRYPT, elgKp, new Date());

        PGPDigestCalculator sha1Calc = new JcaPGPDigestCalculatorProviderBuilder().build().get(HashAlgorithmTags.SHA1);
        PGPKeyRingGenerator keyRingGen = new PGPKeyRingGenerator(PGPSignature.POSITIVE_CERTIFICATION, dsaKeyPair,
            "test", sha1Calc, null, null, new JcaPGPContentSignerBuilder(PGPPublicKey.DSA, HashAlgorithmTags.SHA1),
            new JcePBESecretKeyEncryptorBuilder(tag).setProvider("BC").build(passPhrase));

        keyRingGen.addSubKey(elgKeyPair);

        PGPSecretKeyRing keyRing = keyRingGen.generateSecretKeyRing();

        keyRing.getSecretKey().extractPrivateKey(new BcPBESecretKeyDecryptorBuilder(new BcPGPDigestCalculatorProvider()).build(passPhrase));

        PGPPublicKeyRing pubRing = keyRingGen.generatePublicKeyRing();
        sha1Calc.reset();
        PGPPublicKey vKey = null;
        PGPPublicKey sKey = null;

        Iterator it = pubRing.getPublicKeys();
        while (it.hasNext())
        {
            PGPPublicKey pk = (PGPPublicKey)it.next();
            if (pk.isMasterKey())
            {
                vKey = pk;
            }
            else
            {
                sKey = pk;
            }
        }

        Iterator sIt = sKey.getSignatures();
        while (sIt.hasNext())
        {
            PGPSignature sig = (PGPSignature)sIt.next();

            if (sig.getKeyID() == vKey.getKeyID()
                && sig.getSignatureType() == PGPSignature.SUBKEY_BINDING)
            {
                sig.init(new BcPGPContentVerifierBuilderProvider(), vKey);

                if (!sig.verifyCertification(vKey, sKey))
                {
                    fail("failed to verify sub-key signature.");
                }
            }
        }
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

    private void createWrapperTest(int tag)
        throws Exception
    {
        SecureRandom random = CryptoServicesRegistrar.getSecureRandom();

        X25519KeyPairGenerator gen = new X25519KeyPairGenerator();
        gen.init(new X25519KeyGenerationParameters(random));

        PGPKeyPair dsaKeyPair = new BcPGPKeyPair(PGPPublicKey.ECDH, new PGPKdfParameters(8, tag), gen.generateKeyPair(), new Date());

        encryptDecryptBcTest(dsaKeyPair.getPublicKey(), dsaKeyPair.getPrivateKey());
    }

    public static void main(
        String[] args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new BcImplProviderTest());
    }

    private static class EdDsaSigner
        implements Signer
    {
        private final Signer signer;
        private final Digest digest;
        private final byte[] digBuf;

        EdDsaSigner(Signer signer, Digest digest)
        {
            this.signer = signer;
            this.digest = digest;
            this.digBuf = new byte[digest.getDigestSize()];
        }

        public void init(boolean forSigning, CipherParameters param)
        {
            this.signer.init(forSigning, param);
            this.digest.reset();
        }

        public void update(byte b)
        {
            this.digest.update(b);
        }

        public void update(byte[] in, int off, int len)
        {
            this.digest.update(in, off, len);
        }

        public byte[] generateSignature()
            throws CryptoException, DataLengthException
        {
            digest.doFinal(digBuf, 0);

            signer.update(digBuf, 0, digBuf.length);

            return signer.generateSignature();
        }

        public boolean verifySignature(byte[] signature)
        {
            digest.doFinal(digBuf, 0);

            signer.update(digBuf, 0, digBuf.length);

            return signer.verifySignature(signature);
        }

        public void reset()
        {
            Arrays.clear(digBuf);
            signer.reset();
            digest.reset();
        }
    }
}
