package org.bouncycastle.openpgp.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Date;
import java.util.Iterator;

import org.bouncycastle.bcpg.BCPGInputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.bcpg.CompressionAlgorithmTags;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.bcpg.sig.Features;
import org.bouncycastle.bcpg.sig.KeyFlags;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveGenParameterSpec;
import org.bouncycastle.jce.spec.ElGamalParameterSpec;
import org.bouncycastle.openpgp.PGPCanonicalizedDataGenerator;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPKdfParameters;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPKeyRingGenerator;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPMarker;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPOnePassSignature;
import org.bouncycastle.openpgp.PGPPadding;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.bouncycastle.openpgp.PGPSignatureSubpacketVector;
import org.bouncycastle.openpgp.PGPSignatureVerifier;
import org.bouncycastle.openpgp.PGPSignatureVerifierBuilder;
import org.bouncycastle.openpgp.PGPUserAttributeSubpacketVector;
import org.bouncycastle.openpgp.PGPUserAttributeSubpacketVectorGenerator;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.jcajce.JcaPGPPublicKeyRing;
import org.bouncycastle.openpgp.operator.PGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.bc.BcPBEKeyEncryptionMethodGenerator;
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyEncryptorBuilder;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.test.SimpleTest;
import org.bouncycastle.util.test.UncloseableOutputStream;

public class OpenPGPTest
    extends SimpleTest
{
    static char[] pass = {'h', 'e', 'l', 'l', 'o', ' ', 'w', 'o', 'r', 'l', 'd'};

    public static void main(String[] args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new OpenPGPTest());
    }

    @Override
    public String getName()
    {
        return "OpenpgpTest";
    }

    @Override
    public void performTest()
        throws Exception
    {
        testPGPCanonicalizedDataGenerator();
//        testPGPV3SignatureGenerator();
        testPGPUserAttributeSubpacketVector();
        testPGPLiteralData();
        testPGPEncryptedDataGenerator();
        testPGPSignatureVerifierBuilder();
        testPGPLiteralDataGenerator();
        testContruction();
        testPGPUtil();
        testPGPCompressedDataGenerator();
    }

    public void testPGPCompressedDataGenerator()
        throws IOException
    {
        testException("unknown compression algorithm", "IllegalArgumentException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                new PGPCompressedDataGenerator(110);
            }
        });
        testException("unknown compression level:", "IllegalArgumentException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                new PGPCompressedDataGenerator(CompressionAlgorithmTags.UNCOMPRESSED, 10);
            }
        });

        final PGPCompressedDataGenerator cGen = new PGPCompressedDataGenerator(PGPCompressedData.ZIP);

        final ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        cGen.open(new UncloseableOutputStream(bOut));
        testException("generator already in open state", "IllegalStateException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                cGen.open(new UncloseableOutputStream(bOut));
            }
        });
        testException("generator already in open state", "IllegalStateException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                cGen.open(new UncloseableOutputStream(bOut), new byte[10]);
            }
        });
    }

    public void testPGPUtil()
        throws Exception
    {
        isEquals("SHA1", PGPUtil.getDigestName(HashAlgorithmTags.SHA1));
        isEquals("MD2", PGPUtil.getDigestName(HashAlgorithmTags.MD2));
        isEquals("MD5", PGPUtil.getDigestName(HashAlgorithmTags.MD5));
        isEquals("RIPEMD160", PGPUtil.getDigestName(HashAlgorithmTags.RIPEMD160));
        isEquals("SHA256", PGPUtil.getDigestName(HashAlgorithmTags.SHA256));
        isEquals("SHA3-256", PGPUtil.getDigestName(HashAlgorithmTags.SHA3_256));
        isEquals("SHA3-256", PGPUtil.getDigestName(HashAlgorithmTags.SHA3_256_OLD));
        isEquals("SHA384", PGPUtil.getDigestName(HashAlgorithmTags.SHA384));
        isEquals("SHA3-384", PGPUtil.getDigestName(HashAlgorithmTags.SHA3_384));
        isEquals("SHA512", PGPUtil.getDigestName(HashAlgorithmTags.SHA512));
        isEquals("SHA3-512", PGPUtil.getDigestName(HashAlgorithmTags.SHA3_512));
        isEquals("SHA3-512", PGPUtil.getDigestName(HashAlgorithmTags.SHA3_512_OLD));
        isEquals("SHA224", PGPUtil.getDigestName(HashAlgorithmTags.SHA224));
        isEquals("SHA3-224", PGPUtil.getDigestName(HashAlgorithmTags.SHA3_224));
        isEquals("TIGER", PGPUtil.getDigestName(HashAlgorithmTags.TIGER_192));
        testException("unknown hash algorithm tag in getDigestName: ", "PGPException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                PGPUtil.getDigestName(HashAlgorithmTags.MD4);
            }
        });

        testException("unable to map ", "IllegalArgumentException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                PGPUtil.getDigestIDForName("Test");
            }
        });

        isEquals("SHA1withRSA", PGPUtil.getSignatureName(PublicKeyAlgorithmTags.RSA_GENERAL, HashAlgorithmTags.SHA1));
        isEquals("SHA1withRSA", PGPUtil.getSignatureName(PublicKeyAlgorithmTags.RSA_SIGN, HashAlgorithmTags.SHA1));
        isEquals("SHA1withDSA", PGPUtil.getSignatureName(PublicKeyAlgorithmTags.DSA, HashAlgorithmTags.SHA1));
        isEquals("SHA1withElGamal", PGPUtil.getSignatureName(PublicKeyAlgorithmTags.ELGAMAL_ENCRYPT, HashAlgorithmTags.SHA1));
        isEquals("SHA1withElGamal", PGPUtil.getSignatureName(PublicKeyAlgorithmTags.ELGAMAL_GENERAL, HashAlgorithmTags.SHA1));
        testException("unknown algorithm tag in signature:", "PGPException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                PGPUtil.getSignatureName(PublicKeyAlgorithmTags.RSA_ENCRYPT, HashAlgorithmTags.SHA1);
            }
        });

        isTrue(PGPUtil.getSymmetricCipherName(SymmetricKeyAlgorithmTags.NULL) == null);
        testException("unknown symmetric algorithm: ", "IllegalArgumentException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                PGPUtil.getSymmetricCipherName(101);
            }
        });

        isTrue(!PGPUtil.isKeyBox(new byte[11]));

        isTrue(PGPUtil.makeRandomKey(SymmetricKeyAlgorithmTags.DES, CryptoServicesRegistrar.getSecureRandom()).length == 8);
        testException("unknown symmetric algorithm: ", "PGPException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                PGPUtil.makeRandomKey(SymmetricKeyAlgorithmTags.NULL, CryptoServicesRegistrar.getSecureRandom());
            }
        });
    }

    public void testContruction()
        throws Exception
    {
        String data = "Now is the time for all good men\nTo come to the aid of the party\n";
        PGPCanonicalizedDataGenerator canGen = new PGPCanonicalizedDataGenerator();
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        OutputStream out = canGen.open(bOut, PGPLiteralData.TEXT, PGPLiteralData.CONSOLE, new Date());

        out.write(Strings.toByteArray(data));

        out.close();
        final byte[] input = bOut.toByteArray();

        testException("unexpected packet in stream: ", "IOException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                new PGPCompressedData(new BCPGInputStream(new ByteArrayInputStream(input)));
            }
        });
        //testException("unexpected packet in stream: ", "IOException", ()-> new PGPEncryptedDataList(new BCPGInputStream(new ByteArrayInputStream(input))));
        testException("unexpected packet in stream: ", "IOException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                new PGPMarker(new BCPGInputStream(new ByteArrayInputStream(input)));
            }
        });
        testException("unexpected packet in stream: ", "IOException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                new PGPOnePassSignature(new BCPGInputStream(new ByteArrayInputStream(input)));
            }
        });
        testException("unexpected packet in stream: ", "IOException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                new PGPPadding(new BCPGInputStream(new ByteArrayInputStream(input)));
            }
        });
        //testException("unexpected packet in stream: ", "IOException", ()-> new PGPPublicKeyRing(new BCPGInputStream(new ByteArrayInputStream(input)), new BcKeyFingerprintCalculator()));
        testException("unexpected packet in stream: ", "IOException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                new PGPSignature(new BCPGInputStream(new ByteArrayInputStream(input)));
            }
        });

        testException("unexpected packet in stream: ", "IOException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                new PGPLiteralData(new BCPGInputStream(new ByteArrayInputStream(BcPGPRSATest.sig1)));
            }
        });
    }

    public void testPGPLiteralDataGenerator()
        throws Exception
    {
        final PGPLiteralDataGenerator lGen = new PGPLiteralDataGenerator();
        final String data = "Now is the time for all good men\nTo come to the aid of the party\n";
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        PGPCompressedDataGenerator cGen = new PGPCompressedDataGenerator(
            PGPCompressedData.ZIP);
        final BCPGOutputStream bcOut = new BCPGOutputStream(
            cGen.open(new UncloseableOutputStream(bOut)));
        final Date testDate = new Date((System.currentTimeMillis() / 1000) * 1000);
        lGen.open(
            new UncloseableOutputStream(bcOut),
            PGPLiteralData.BINARY,
            "_CONSOLE",
            data.getBytes().length,
            testDate);
        testException("generator already in open state", "IllegalStateException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                lGen.open(
                            new UncloseableOutputStream(bcOut),
                            PGPLiteralData.BINARY,
                            "_CONSOLE",
                            data.getBytes().length,
                            testDate);
            }
        });
        testException("generator already in open state", "IllegalStateException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                lGen.open(
                            new UncloseableOutputStream(bcOut),
                            PGPLiteralData.BINARY,
                            "_CONSOLE",
                            testDate,
                            new byte[10]);
            }
        });
    }

    public void testPGPSignatureVerifierBuilder()
        throws Exception
    {
        PGPPublicKeyRing pgpPub = new PGPPublicKeyRing(PGPKeyRingTest.pub7, new JcaKeyFingerprintCalculator());
        Iterator it = pgpPub.getPublicKeys();
        PGPPublicKey masterKey = null;

        while (it.hasNext())
        {
            PGPPublicKey k = (PGPPublicKey)it.next();

            if (k.isMasterKey())
            {
                masterKey = k;
            }
        }

        int count = 0;
        PGPSignature sig = null;
        Iterator sIt = masterKey.getSignaturesOfType(PGPSignature.KEY_REVOCATION);

        while (sIt.hasNext())
        {
            sig = (PGPSignature)sIt.next();
            count++;
        }

        if (count != 1)
        {
            fail("wrong number of revocations in test7.");
        }
        PGPSignatureVerifier verifier = new PGPSignatureVerifierBuilder(new JcaPGPContentVerifierBuilderProvider(), masterKey).buildKeyRevocationVerifier(sig, masterKey);
        isTrue(verifier.getSignatureType() == PGPSignature.KEY_REVOCATION);
        isTrue(verifier.isVerified());
        final PGPSignature tmpFinalSig1 = sig;
        final PGPPublicKey tmpFinalPubKey1 = masterKey;
        testException("PGPSignature not initialised - call init().", "PGPException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                tmpFinalSig1.verifyCertification(tmpFinalPubKey1);
            }
        });

        pgpPub = new PGPPublicKeyRing(PGPKeyRingTest.pub7sub, new JcaKeyFingerprintCalculator());
        it = pgpPub.getPublicKeys();
        masterKey = null;

        while (it.hasNext())
        {
            PGPPublicKey k = (PGPPublicKey)it.next();

            if (k.isMasterKey())
            {
                masterKey = k;
                continue;
            }

            count = 0;
            sig = null;
            sIt = k.getSignaturesOfType(PGPSignature.SUBKEY_REVOCATION);

            while (sIt.hasNext())
            {
                sig = (PGPSignature)sIt.next();
                count++;
            }

            if (count != 1)
            {
                fail("wrong number of revocations in test7 subkey.");
            }

            verifier = new PGPSignatureVerifierBuilder(new JcaPGPContentVerifierBuilderProvider(), masterKey).buildSubKeyRevocationVerifier(sig, masterKey, k);
            isTrue(verifier.getSignatureType() == PGPSignature.SUBKEY_REVOCATION);
            isTrue(verifier.isVerified());

            testException("PGPSignature not initialised - call init().", "PGPException", new TestExceptionOperation()
            {
                @Override
                public void operation()
                    throws Exception
                {
                    tmpFinalSig1.verifyCertification(tmpFinalPubKey1, tmpFinalPubKey1);
                }
            });
        }

        PGPDigestCalculator digestCalculator = new BcPGPDigestCalculatorProvider().get(HashAlgorithmTags.SHA1);
        KeyPairGenerator generator;
        KeyPair pair;

        // Generate master key

        generator = KeyPairGenerator.getInstance("ECDSA", BouncyCastleProvider.PROVIDER_NAME);
        generator.initialize(new ECNamedCurveGenParameterSpec("P-256"));

        pair = generator.generateKeyPair();
        PGPKeyPair pgpMasterKey = new JcaPGPKeyPair(PublicKeyAlgorithmTags.ECDSA, pair, new Date());

        PGPSignatureSubpacketGenerator hashed = new PGPSignatureSubpacketGenerator();
        hashed.addNotationData(false, true, "test@bouncycastle.org", "hashedNotation");
        PGPSignatureSubpacketGenerator unhashed = new PGPSignatureSubpacketGenerator();

        PGPContentSignerBuilder signerBuilder = new BcPGPContentSignerBuilder(PublicKeyAlgorithmTags.ECDSA, HashAlgorithmTags.SHA512);
        PGPKeyRingGenerator keyRingGenerator = new PGPKeyRingGenerator(
            pgpMasterKey, digestCalculator, hashed.generate(), unhashed.generate(), signerBuilder, null);

        PGPPublicKey publicKey = keyRingGenerator.generateSecretKeyRing().getPublicKey();

        Iterator<PGPSignature> signatures = publicKey.getSignaturesOfType(PGPSignature.DIRECT_KEY);
        isTrue(signatures.hasNext());

        PGPSignature signature = (PGPSignature)signatures.next();
        isTrue(!signatures.hasNext());

        verifier = new PGPSignatureVerifierBuilder(new JcaPGPContentVerifierBuilderProvider().setProvider("BC"), publicKey).buildDirectKeyVerifier(signature, publicKey);
        isTrue(verifier.isVerified());
        isTrue(verifier.getSignatureType() == PGPSignature.DIRECT_KEY);


        // Generate master key
        generator = KeyPairGenerator.getInstance("ECDSA", BouncyCastleProvider.PROVIDER_NAME);
        generator.initialize(new ECNamedCurveGenParameterSpec("P-256"));

        pair = generator.generateKeyPair();
        pgpMasterKey = new JcaPGPKeyPair(PublicKeyAlgorithmTags.ECDSA, pair, new Date());

        PGPSignatureSubpacketGenerator subPackets = new PGPSignatureSubpacketGenerator();
        subPackets.setKeyFlags(false, KeyFlags.AUTHENTICATION & KeyFlags.CERTIFY_OTHER & KeyFlags.SIGN_DATA);
        subPackets.setPreferredSymmetricAlgorithms(false, new int[]{
            SymmetricKeyAlgorithmTags.AES_256,
            SymmetricKeyAlgorithmTags.AES_192,
            SymmetricKeyAlgorithmTags.AES_128});
        subPackets.setPreferredHashAlgorithms(false, new int[]{
            HashAlgorithmTags.SHA512,
            HashAlgorithmTags.SHA384,
            HashAlgorithmTags.SHA256,
            HashAlgorithmTags.SHA224});
        subPackets.setPreferredCompressionAlgorithms(false, new int[]{
            CompressionAlgorithmTags.ZLIB,
            CompressionAlgorithmTags.BZIP2,
            CompressionAlgorithmTags.ZIP,
            CompressionAlgorithmTags.UNCOMPRESSED});
        subPackets.setFeature(false, Features.FEATURE_MODIFICATION_DETECTION);

        // Generate sub key

        generator = KeyPairGenerator.getInstance("ECDH", BouncyCastleProvider.PROVIDER_NAME);
        generator.initialize(new ECNamedCurveGenParameterSpec("P-256"));

        KeyPair encPair = generator.generateKeyPair();
        PGPKeyPair encSubKey = new JcaPGPKeyPair(PublicKeyAlgorithmTags.ECDH, encPair, new Date());
        KeyPair sigPair = generator.generateKeyPair();
        PGPKeyPair sigSubKey = new JcaPGPKeyPair(PublicKeyAlgorithmTags.ECDSA, sigPair, new Date());

        // Assemble key

        PGPDigestCalculator calculator = new JcaPGPDigestCalculatorProviderBuilder()
            .setProvider(BouncyCastleProvider.PROVIDER_NAME)
            .build()
            .get(HashAlgorithmTags.SHA1);

        signerBuilder = new JcaPGPContentSignerBuilder(
            pgpMasterKey.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA512)
            .setProvider(BouncyCastleProvider.PROVIDER_NAME)
            .setDigestProvider(new BouncyCastleProvider());

        PGPKeyRingGenerator pgpGenerator = new PGPKeyRingGenerator(PGPSignature.POSITIVE_CERTIFICATION,
            pgpMasterKey, "alice@wonderland.lit", calculator, subPackets.generate(), null,
            signerBuilder, null);

        // Add sub key

        subPackets.setKeyFlags(false, KeyFlags.ENCRYPT_STORAGE & KeyFlags.ENCRYPT_COMMS);

        pgpGenerator.addSubKey(encSubKey, subPackets.generate(), null);

        pgpGenerator.addSubKey(sigSubKey, subPackets.generate(), null,
            new JcaPGPContentSignerBuilder(
                sigSubKey.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA256)
                .setProvider("BC").setDigestProvider("BC"));

        // Generate SecretKeyRing

        PGPSecretKeyRing secretKeys = pgpGenerator.generateSecretKeyRing();

        PGPPublicKeyRing publicKeys = pgpGenerator.generatePublicKeyRing();

        checkPublicKeyRing(secretKeys, publicKeys.getEncoded());
        // Extract the public keys
        ByteArrayOutputStream bOut = new ByteArrayOutputStream(2048);
        Iterator<PGPPublicKey> iterator = secretKeys.getPublicKeys();
        count = 0;
        while (iterator.hasNext())
        {
            PGPPublicKey key = (PGPPublicKey)iterator.next();

            if (!key.isMasterKey() && !key.isEncryptionKey())
            {
                PGPSignature pgpSig = (PGPSignature)key.getSignaturesForKeyID(pgpMasterKey.getKeyID()).next();

                isTrue(pgpSig.hasSubpackets());

                PGPSignatureSubpacketVector subP = pgpSig.getHashedSubPackets();

                verifier = new PGPSignatureVerifierBuilder(new JcaPGPContentVerifierBuilderProvider().setProvider("BC"), key)
                    .buildPrimaryKeyBindingVerifier(subP.getEmbeddedSignatures().get(0), pgpMasterKey.getPublicKey(), key);
                isTrue(verifier.isVerified());
                isTrue(verifier.getSignatureType() == PGPSignature.PRIMARYKEY_BINDING);

                final PGPSignature tmpFinalSig = sig;
                final PGPPublicKey tmpFInalPubKey = key;
                testException("PGPSignature not initialised - call init().", "PGPException", new TestExceptionOperation()
                {
                    @Override
                    public void operation()
                        throws Exception
                    {
                        tmpFinalSig.verifyCertification(tmpFInalPubKey);
                    }
                });

            }
            bOut.write(key.getEncoded());
            count++;
        }

        isTrue(count == 3);


        pgpPub = new PGPPublicKeyRing(PGPRSATest.embeddedJPEGKey, new JcaKeyFingerprintCalculator());

        PGPPublicKey pubKey = pgpPub.getPublicKey();

        it = pubKey.getUserAttributes();
        count = 0;
        PGPUserAttributeSubpacketVector attributes = null;
        while (it.hasNext())
        {
            attributes = (PGPUserAttributeSubpacketVector)it.next();

            Iterator sigs = pubKey.getSignaturesForUserAttribute(attributes);
            int sigCount = 0;
            while (sigs.hasNext())
            {
                sig = (PGPSignature)sigs.next();

                verifier = new PGPSignatureVerifierBuilder(new JcaPGPContentVerifierBuilderProvider().setProvider("BC"), pubKey).buildCertificationVerifier(sig, attributes, pubKey);
                isTrue(verifier.isVerified());
                isTrue(PGPSignature.isCertification(verifier.getSignatureType()));
                final PGPSignature tmpFinalSig = sig;
                final PGPUserAttributeSubpacketVector tmpFinalAttributes = attributes;
                final PGPPublicKey tmpFinalPubKey = pubKey;
                testException("PGPSignature not initialised - call init().", "PGPException", new TestExceptionOperation()
                {
                    @Override
                    public void operation()
                        throws Exception
                    {
                        tmpFinalSig.verifyCertification(tmpFinalAttributes, tmpFinalPubKey);
                    }
                });
                sigCount++;
            }

            if (sigCount != 1)
            {
                fail("Failed user attributes signature check");
            }
            count++;
        }

        if (count != 1)
        {
            fail("didn't find user attributes");
        }
        final PGPSignature finalSig2 = sig;
        final PGPPublicKey finalPubKey2 = pubKey;

        PGPPublicKeyRing pgpRing = new JcaPGPPublicKeyRing(new ByteArrayInputStream(PGPKeyRingTest.problemUserID));

        byte[] enc = pgpRing.getEncoded();

        if (!Arrays.areEqual(PGPKeyRingTest.problemUserID, enc))
        {
            fail("encoded key does not match original");
        }

        pubKey = pgpRing.getPublicKey();

        it = pubKey.getRawUserIDs();

        final byte[] rawID = (byte[])it.next();

        it = pubKey.getSignaturesForID(rawID);

        sig = (PGPSignature)it.next();
        verifier = new PGPSignatureVerifierBuilder(new JcaPGPContentVerifierBuilderProvider().setProvider("BC"), pubKey).buildCertificationVerifier(sig, rawID, pubKey);
        isTrue(verifier.isVerified());
        isTrue(PGPSignature.isCertification(verifier.getSignatureType()));

        testException("PGPSignature not initialised - call init().", "PGPException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                tmpFinalSig1.verifyCertification(rawID, tmpFinalPubKey1);
            }
        });

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
        PGPKeyPair dsaKeyPair = new JcaPGPKeyPair(PGPPublicKey.DSA, new PGPKdfParameters(HashAlgorithmTags.SHA256, SymmetricKeyAlgorithmTags.AES_128), dsaKp, new Date());
        PGPKeyPair elgKeyPair = new JcaPGPKeyPair(PGPPublicKey.ELGAMAL_ENCRYPT, elgKp, new Date());

        PGPDigestCalculator sha1Calc = new JcaPGPDigestCalculatorProviderBuilder().build().get(HashAlgorithmTags.SHA1);
        PGPKeyRingGenerator keyRingGen = new PGPKeyRingGenerator(PGPSignature.POSITIVE_CERTIFICATION, dsaKeyPair,
            "test", sha1Calc, null, null, new JcaPGPContentSignerBuilder(PGPPublicKey.DSA, HashAlgorithmTags.SHA1), new JcePBESecretKeyEncryptorBuilder(PGPEncryptedData.AES_256).setProvider("BC").build(passPhrase));

        keyRingGen.addSubKey(elgKeyPair);

        PGPSecretKeyRing keyRing = keyRingGen.generateSecretKeyRing();

        keyRing.getSecretKey().extractPrivateKey(new BcPBESecretKeyDecryptorBuilder(new BcPGPDigestCalculatorProvider()).build(passPhrase));

        PGPPublicKeyRing pubRing = keyRingGen.generatePublicKeyRing();

        PGPPublicKey vKey = null;
        PGPPublicKey sKey = null;

        it = pubRing.getPublicKeys();
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

        sig = new PGPSignatureList((PGPSignature)sKey.getSignatures().next()).get(0);

        if (sig.getKeyID() == vKey.getKeyID())
        {
            verifier = new PGPSignatureVerifierBuilder(new JcaPGPContentVerifierBuilderProvider().setProvider("BC"), vKey).buildSubKeyBindingVerifier(sig, vKey, sKey);
            isTrue(verifier.isVerified());
            isTrue(verifier.getSignatureType() == PGPSignature.SUBKEY_BINDING);

        }
        else
        {
            fail("");
        }


        final PGPPublicKey v_Key = vKey;
        final PGPSignature finalSig = sig;
        final PGPPublicKey s_Key = sKey;
        testException("signature is not a direct key signature", "PGPException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                new PGPSignatureVerifierBuilder
                            (new JcaPGPContentVerifierBuilderProvider().setProvider("BC"), v_Key).buildDirectKeyVerifier(finalSig, v_Key);
            }
        });
        testException("signature is not a key revocation signature", "PGPException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                new PGPSignatureVerifierBuilder
                            (new JcaPGPContentVerifierBuilderProvider().setProvider("BC"), v_Key).buildKeyRevocationVerifier(finalSig, v_Key);
            }
        } );
        testException("signature is not a primary key binding signature", "PGPException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                new PGPSignatureVerifierBuilder
                           (new JcaPGPContentVerifierBuilderProvider().setProvider("BC"), v_Key).buildPrimaryKeyBindingVerifier(finalSig, v_Key, v_Key);
            }
        });
        testException("signature is not a subkey binding signature", "PGPException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                new PGPSignatureVerifierBuilder
                           (new JcaPGPContentVerifierBuilderProvider().setProvider("BC"), s_Key).buildSubKeyBindingVerifier(finalSig2, s_Key, s_Key);
            }
        });
        finalSig.init(new JcaPGPContentVerifierBuilderProvider().setProvider("BC"), v_Key);
        final PGPUserAttributeSubpacketVector finalAttributes = attributes;
        testException("signature is neither a certification signature nor a certification revocation.", "PGPException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                finalSig.verifyCertification(finalAttributes, v_Key);
            }
        });
        testException("signature is neither a certification signature nor a certification revocation.", "PGPException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                finalSig.verifyCertification(rawID, v_Key);
            }
        });

        finalSig2.init(new JcaPGPContentVerifierBuilderProvider().setProvider("BC"), finalPubKey2);
        testException("signature is not a key binding signature.", "PGPException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                finalSig2.verifyCertification(finalPubKey2, finalPubKey2);
            }
        });

        testException("These are different signatures.", "IllegalArgumentException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                PGPSignature.join(finalSig, finalSig2);
            }
        });

        keyRingGen = new PGPKeyRingGenerator(PGPSignature.CERTIFICATION_REVOCATION, dsaKeyPair,
            "test", sha1Calc, null, null, new JcaPGPContentSignerBuilder(PGPPublicKey.DSA, HashAlgorithmTags.SHA1)
            .setProvider(new BouncyCastleProvider()).setSecureRandom(CryptoServicesRegistrar.getSecureRandom()),
            new JcePBESecretKeyEncryptorBuilder(PGPEncryptedData.AES_256, 2).setProvider(new BouncyCastleProvider()).build(passPhrase));

        keyRingGen.addSubKey(elgKeyPair);

        keyRing = keyRingGen.generateSecretKeyRing();

        keyRing.getSecretKey().extractPrivateKey(new BcPBESecretKeyDecryptorBuilder(new BcPGPDigestCalculatorProvider()).build(passPhrase));

        pubRing = keyRingGen.generatePublicKeyRing();
        it = pubRing.getPublicKeys();
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
        final PGPSignature finalSig3 = (PGPSignature)sKey.getSignatures().next();
        testException("signature is neither a certification signature nor a certification revocation", "PGPException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                new PGPSignatureVerifierBuilder
                           (new JcaPGPContentVerifierBuilderProvider().setProvider("BC"), v_Key).buildCertificationVerifier(finalSig3, rawID, v_Key);
            }
        });
        testException("signature is neither a certification signature nor a certification revocation", "PGPException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                new PGPSignatureVerifierBuilder
                            (new JcaPGPContentVerifierBuilderProvider().setProvider("BC"), v_Key).buildCertificationVerifier(finalSig3, finalAttributes, v_Key);
            }
        });
        testException("signature is not a primary key binding signature", "PGPException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                new PGPSignatureVerifierBuilder
                            (new JcaPGPContentVerifierBuilderProvider().setProvider("BC"), v_Key).buildSubKeyRevocationVerifier(finalSig3, v_Key, v_Key);
            }
        });

        isTrue(finalSig2.isCertification());
        isTrue(!finalSig3.isCertification());
    }

    private void checkPublicKeyRing(PGPSecretKeyRing secretKeys, byte[] encRing)
        throws IOException
    {
        Iterator<PGPPublicKey> iterator;
        PGPPublicKeyRing publicKeys = new PGPPublicKeyRing(encRing, new BcKeyFingerprintCalculator());

        // Check, if all public keys made it to the new public key ring
        iterator = secretKeys.getPublicKeys();
        while (iterator.hasNext())
        {
            isTrue(publicKeys.getPublicKey(((PGPPublicKey)iterator.next()).getKeyID()) != null);
        }
    }

    public void testPGPEncryptedDataGenerator()
        throws Exception
    {
        final ByteArrayOutputStream cbOut = new ByteArrayOutputStream();
        final PGPEncryptedDataGenerator cPk = new PGPEncryptedDataGenerator(new BcPGPDataEncryptorBuilder(PGPEncryptedData.CAST5).setSecureRandom(new SecureRandom()));
        final ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        testException("no encryption methods specified", "IllegalStateException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                cPk.open(new UncloseableOutputStream(cbOut), bOut.toByteArray().length);
            }
        });

        cPk.addMethod(new BcPBEKeyEncryptionMethodGenerator(pass, 2).setSecureRandom(CryptoServicesRegistrar.getSecureRandom()));
        cPk.open(new UncloseableOutputStream(cbOut), bOut.toByteArray().length);
        testException("generator already in open state", "IllegalStateException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                cPk.open(new UncloseableOutputStream(cbOut), bOut.toByteArray().length);
            }
        });
    }

    public void testPGPLiteralData()
        throws Exception
    {
        PGPObjectFactory pgpF = new PGPObjectFactory(BcPGPRSATest.enc1, new BcKeyFingerprintCalculator());

        PGPSecretKeyRing pgpPriv = new PGPSecretKeyRing(BcPGPRSATest.subKey, new BcKeyFingerprintCalculator());
        PGPEncryptedDataList encList = (PGPEncryptedDataList)pgpF.nextObject();

        PGPPublicKeyEncryptedData encP = (PGPPublicKeyEncryptedData)encList.get(0);
        isEquals(encP.getAlgorithm(), 1);
        isEquals(encP.getVersion(), 3);
        PGPPrivateKey pgpPrivKey = pgpPriv.getSecretKey(encP.getKeyID()).extractPrivateKey(new BcPBESecretKeyDecryptorBuilder(new BcPGPDigestCalculatorProvider()).build(pass));

        InputStream clear = encP.getDataStream(new BcPublicKeyDataDecryptorFactory(pgpPrivKey));

        PGPObjectFactory pgpFact = new PGPObjectFactory(clear, new BcKeyFingerprintCalculator());

        PGPCompressedData c1 = (PGPCompressedData)pgpFact.nextObject();

        PGPLiteralData ld = new PGPLiteralData(c1.getDataStream());

        if (!ld.getFileName().equals("test.txt"))
        {
            throw new RuntimeException("wrong filename in packet");
        }
    }

    public void testPGPUserAttributeSubpacketVector()
    {
        PGPUserAttributeSubpacketVector vector = PGPUserAttributeSubpacketVector.fromSubpackets(null);
        isTrue(vector.getSubpacket(0) == null);
        isTrue(vector.getImageAttribute() == null);

        testException("attempt to set null image", "IllegalArgumentException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                new PGPUserAttributeSubpacketVectorGenerator().setImageAttribute(0, null);
            }
        });
    }

    public void testPGPCanonicalizedDataGenerator()
        throws IOException
    {
        final PGPCanonicalizedDataGenerator canGen = new PGPCanonicalizedDataGenerator(false);
        final ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        final File bcFile = File.createTempFile("bcpgp", ".back");
        canGen.open(bOut, PGPLiteralData.TEXT, bcFile);
        testException("generator already in open state", "IllegalStateException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                canGen.open(bOut, PGPLiteralData.TEXT, bcFile);
            }
        });
        testException("generator already in open state", "IllegalStateException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                canGen.open(bOut, PGPLiteralData.TEXT, bcFile.getName(),
                            new Date(bcFile.lastModified()), bcFile);
            }
        });
        testException("generator already in open state", "IllegalStateException", new TestExceptionOperation()
        {
            @Override
            public void operation()
                throws Exception
            {
                canGen.open(bOut, PGPLiteralData.TEXT, bcFile.getName(),
                            new Date(bcFile.lastModified()), new byte[10]);
            }
        });
    }

//    public void testPGPV3SignatureGenerator()
//        throws Exception
//    {
//        char[] passPhrase = "hello".toCharArray();
//        String data = "hello world!";
//        String  newPass = "newPass";
//        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "BC");
//
//        kpg.initialize(1024);
//
//        KeyPair kp = kpg.generateKeyPair();
//        PGPSecretKey secretKey = new PGPSecretKey(
//            PGPSignature.DEFAULT_CERTIFICATION,
//            new JcaPGPKeyPair(PublicKeyAlgorithmTags.RSA_SIGN, kp, new Date()), "fred",
//            null, null, new JcaPGPContentSignerBuilder(PublicKeyAlgorithmTags.RSA_SIGN, HashAlgorithmTags.SHA1).setProvider("BC"),
//            new JcePBESecretKeyEncryptorBuilder(SymmetricKeyAlgorithmTags.AES_256).build(passPhrase));
//        secretKey = PGPSecretKey.copyWithNewPassword(secretKey, new JcePBESecretKeyDecryptorBuilder(new JcaPGPDigestCalculatorProviderBuilder().setProvider("BC").build()).setProvider("BC").build(passPhrase), new JcePBESecretKeyEncryptorBuilder(secretKey.getKeyEncryptionAlgorithm()).setProvider("BC").setSecureRandom(new SecureRandom()).build(newPass.toCharArray()));
//
//        final PGPPrivateKey pgpPrivKey = secretKey.extractPrivateKey(new JcePBESecretKeyDecryptorBuilder(new JcaPGPDigestCalculatorProviderBuilder().setProvider("BC").build()).setProvider("BC").build(newPass.toCharArray()));
//
//        final PGPV3SignatureGenerator sGenV3 = new PGPV3SignatureGenerator(new JcaPGPContentSignerBuilder(PGPPublicKey.DSA, PGPUtil.SHA1).setProvider("BC"));
//
//        testException("key algorithm mismatch", "PGPException", ()->sGenV3.init(PGPSignature.BINARY_DOCUMENT, pgpPrivKey));
//    }
}
