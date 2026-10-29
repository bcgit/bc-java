package org.bouncycastle.openpgp.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.Security;
import java.util.Date;

import org.bouncycastle.bcpg.AEADAlgorithmTags;
import org.bouncycastle.bcpg.BCPGInputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.MLDSACompositePublicBCPGKey;
import org.bouncycastle.bcpg.MLKEMCompositePublicBCPGKey;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyEncSessionPacket;
import org.bouncycastle.bcpg.PublicKeyPacket;
import org.bouncycastle.bcpg.PublicKeyUtils;
import org.bouncycastle.bcpg.S2K;
import org.bouncycastle.bcpg.SLHDSAPublicBCPGKey;
import org.bouncycastle.bcpg.SignaturePacket;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.openpgp.bc.BcPGPObjectFactory;
import org.bouncycastle.openpgp.operator.PGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.PGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.PGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.PGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.PGPKeyPairGenerator;
import org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.PublicKeyKeyEncryptionMethodGenerator;
import org.bouncycastle.openpgp.operator.bc.BcAEADSecretKeyEncryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.bc.BcPGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.bc.BcPGPKeyPair;
import org.bouncycastle.openpgp.operator.bc.BcPGPKeyPairGeneratorProvider;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyKeyEncryptionMethodGenerator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPairGeneratorProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyDataDecryptorFactoryBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.io.Streams;

/**
 * Round trips of the RFC 9980 algorithms through the lightweight and JCA operators - key generation and
 * conversion, signing and verification, encryption and decryption (v6 PKESK with v2 SEIPD, and the v3 PKESK
 * with v1 SEIPD a v4 ML-KEM-768+X25519 key allows), secret key protection - in every Bc/Jca combination,
 * plus the rejections RFC 9980 requires: non-v6 keys and signatures, digests under 256 bits, non-AES v3 PKESK
 * packets, a tampered symmetric algorithm octet, a corrupted component signature, and the sec. 7.2 rule on
 * binding signature hashes.
 */
public class PGPRFC9980KeyPairTest
    extends AbstractPgpKeyPairTest
{
    private static final int[] SIGNATURE_ALGORITHMS = {
        PublicKeyAlgorithmTags.MLDSA65_Ed25519, PublicKeyAlgorithmTags.MLDSA87_Ed448,
        PublicKeyAlgorithmTags.SLHDSA_SHAKE_128s, PublicKeyAlgorithmTags.SLHDSA_SHAKE_128f, PublicKeyAlgorithmTags.SLHDSA_SHAKE_256s
    };
    private static final int[] KEM_ALGORITHMS = {
        PublicKeyAlgorithmTags.MLKEM768_X25519, PublicKeyAlgorithmTags.MLKEM1024_X448
    };
    private static final byte[] DATA = Strings.toUTF8ByteArray("Hello, World!\n");

    public String getName()
    {
        return "PGPRFC9980KeyPairTest";
    }

    public void performTest()
        throws Exception
    {
        Date creationTime = currentTimeRounded();

        for (int i = 0; i != SIGNATURE_ALGORITHMS.length; i++)
        {
            testSigningKeyPair(SIGNATURE_ALGORITHMS[i], creationTime);
        }
        for (int i = 0; i != KEM_ALGORITHMS.length; i++)
        {
            testEncryptionKeyPair(KEM_ALGORITHMS[i], creationTime);
        }

        testV4MLKEM768X25519(creationTime);
        testV4KeyGenerationIsRejected(creationTime);
        testSmallDigestsAreRejected(creationTime);
        testV4SignaturesAreRejected(creationTime);
        testCorruptedCompositeSignature(creationTime);
        testV3PKESKRequiresAES(creationTime);
        testTamperedV3SymmetricAlgorithmOctet(creationTime);
        testTruncatedPKESKIsRejected(creationTime);
        testBindingSignatureHashRule(creationTime);
    }

    private static PGPKeyPair generate(PGPKeyPairGenerator gen, int algorithm)
        throws PGPException
    {
        switch (algorithm)
        {
        case PublicKeyAlgorithmTags.MLDSA65_Ed25519:
            return gen.generateMLDSA65Ed25519KeyPair();
        case PublicKeyAlgorithmTags.MLDSA87_Ed448:
            return gen.generateMLDSA87Ed448KeyPair();
        case PublicKeyAlgorithmTags.SLHDSA_SHAKE_128s:
            return gen.generateSLHDSAShake128sKeyPair();
        case PublicKeyAlgorithmTags.SLHDSA_SHAKE_128f:
            return gen.generateSLHDSAShake128fKeyPair();
        case PublicKeyAlgorithmTags.SLHDSA_SHAKE_256s:
            return gen.generateSLHDSAShake256sKeyPair();
        case PublicKeyAlgorithmTags.MLKEM768_X25519:
            return gen.generateMLKEM768X25519KeyPair();
        case PublicKeyAlgorithmTags.MLKEM1024_X448:
            return gen.generateMLKEM1024X448KeyPair();
        default:
            throw new IllegalArgumentException("not an RFC 9980 algorithm: " + algorithm);
        }
    }

    private PGPKeyPairGenerator bcGenerator(int version, Date creationTime)
    {
        return new BcPGPKeyPairGeneratorProvider().get(version, creationTime);
    }

    private PGPKeyPairGenerator jcaGenerator(int version, Date creationTime)
    {
        return new JcaPGPKeyPairGeneratorProvider().setProvider("BC").get(version, creationTime);
    }

    private PGPContentSignerBuilder signerBuilder(boolean bc, int algorithm, int hashAlgorithm)
    {
        return bc ? (PGPContentSignerBuilder)new BcPGPContentSignerBuilder(algorithm, hashAlgorithm)
            : new JcaPGPContentSignerBuilder(algorithm, hashAlgorithm).setProvider("BC");
    }

    private PGPContentVerifierBuilderProvider verifierProvider(boolean bc)
    {
        return bc ? (PGPContentVerifierBuilderProvider)new BcPGPContentVerifierBuilderProvider()
            : new JcaPGPContentVerifierBuilderProvider().setProvider("BC");
    }

    private PGPSignature sign(PGPKeyPair keyPair, boolean bc, int hashAlgorithm, byte[] data)
        throws PGPException, IOException
    {
        PGPSignatureGenerator sigGen = new PGPSignatureGenerator(
            signerBuilder(bc, keyPair.getPublicKey().getAlgorithm(), hashAlgorithm), keyPair.getPublicKey());
        sigGen.init(PGPSignature.BINARY_DOCUMENT, keyPair.getPrivateKey());
        sigGen.update(data);
        PGPSignature sig = sigGen.generate();

        // through the encoding
        PGPObjectFactory objFac = new BcPGPObjectFactory(sig.getEncoded());
        return ((PGPSignatureList)objFac.nextObject()).get(0);
    }

    private boolean verify(PGPSignature sig, PGPPublicKey publicKey, boolean bc, byte[] data)
        throws PGPException
    {
        sig.init(verifierProvider(bc), publicKey);
        sig.update(data);
        return sig.verify();
    }

    private void checkKeyPairEncodings(String label, PGPKeyPair a, PGPKeyPair b)
        throws IOException
    {
        isTrue(label + ": public key packets", Arrays.areEqual(a.getPublicKey().getEncoded(), b.getPublicKey().getEncoded()));
        isTrue(label + ": fingerprints", Arrays.areEqual(a.getPublicKey().getFingerprint(), b.getPublicKey().getFingerprint()));
        isTrue(label + ": private key material",
            Arrays.areEqual(a.getPrivateKey().getPrivateKeyDataPacket().getEncoded(), b.getPrivateKey().getPrivateKeyDataPacket().getEncoded()));
    }

    private void testSigningKeyPair(int algorithm, Date creationTime)
        throws Exception
    {
        String label = "signing algorithm " + algorithm;
        PGPKeyPair bcKp = generate(bcGenerator(PublicKeyPacket.VERSION_6, creationTime), algorithm);
        PGPKeyPair jcaKp = generate(jcaGenerator(PublicKeyPacket.VERSION_6, creationTime), algorithm);

        isEquals(label + ": algorithm", algorithm, bcKp.getPublicKey().getAlgorithm());
        isEquals(label + ": version", PublicKeyPacket.VERSION_6, bcKp.getPublicKey().getVersion());
        isTrue(label + ": signing key", PublicKeyUtils.isSigningAlgorithm(bcKp.getPublicKey().getAlgorithm()));
        isTrue(label + ": not an encryption key", !bcKp.getPublicKey().isEncryptionKey());
        isEquals(label + ": creation time", creationTime, bcKp.getPublicKey().getCreationTime());
        if (PublicKeyUtils.isMLDSACompositeAlgorithm(algorithm))
        {
            isTrue(label + ": key material", bcKp.getPublicKey().getPublicKeyPacket().getKey() instanceof MLDSACompositePublicBCPGKey);
            isTrue(label + ": key material", jcaKp.getPublicKey().getPublicKeyPacket().getKey() instanceof MLDSACompositePublicBCPGKey);
        }
        else
        {
            isTrue(label + ": key material", bcKp.getPublicKey().getPublicKeyPacket().getKey() instanceof SLHDSAPublicBCPGKey);
            isTrue(label + ": key material", jcaKp.getPublicKey().getPublicKeyPacket().getKey() instanceof SLHDSAPublicBCPGKey);
        }
        isTrue(label + ": two generators give two keys",
            !Arrays.areEqual(bcKp.getPublicKey().getFingerprint(), jcaKp.getPublicKey().getFingerprint()));

        // lightweight <-> JCA conversion of both key pairs preserves the OpenPGP encodings
        checkKeyPairEncodings(label + " bc->jca", bcKp, toJcaKeyPair((BcPGPKeyPair)bcKp));
        checkKeyPairEncodings(label + " jca->bc", jcaKp, toBcKeyPair((JcaPGPKeyPair)jcaKp));

        // sign and verify in every combination of operators, with SHA-256 and SHA-512
        PGPKeyPair[] pairs = { bcKp, jcaKp };
        int[] hashes = { HashAlgorithmTags.SHA256, HashAlgorithmTags.SHA512, HashAlgorithmTags.SHA3_256 };
        for (int p = 0; p != pairs.length; p++)
        {
            for (int h = 0; h != hashes.length; h++)
            {
                PGPSignature bcSig = sign(pairs[p], true, hashes[h], DATA);
                PGPSignature jcaSig = sign(pairs[p], false, hashes[h], DATA);
                isEquals(label + ": signature version", SignaturePacket.VERSION_6, bcSig.getVersion());
                isEquals(label + ": signature algorithm", algorithm, bcSig.getKeyAlgorithm());
                int sigLen = PublicKeyUtils.isMLDSACompositeAlgorithm(algorithm)
                    ? MLDSACompositePublicBCPGKey.getSignatureLength(algorithm) : SLHDSAPublicBCPGKey.getSignatureLength(algorithm);
                isEquals(label + ": signature length", sigLen, bcSig.getSignature().length);
                isEquals(label + ": signature length", sigLen, jcaSig.getSignature().length);

                isTrue(label + ": bc sig / bc verify", verify(bcSig, pairs[p].getPublicKey(), true, DATA));
                isTrue(label + ": bc sig / jca verify", verify(bcSig, pairs[p].getPublicKey(), false, DATA));
                isTrue(label + ": jca sig / bc verify", verify(jcaSig, pairs[p].getPublicKey(), true, DATA));
                isTrue(label + ": jca sig / jca verify", verify(jcaSig, pairs[p].getPublicKey(), false, DATA));

                byte[] other = Strings.toUTF8ByteArray("Hello, World?\n");
                isTrue(label + ": bc verify other data", !verify(bcSig, pairs[p].getPublicKey(), true, other));
                isTrue(label + ": jca verify other data", !verify(jcaSig, pairs[p].getPublicKey(), false, other));
                isTrue(label + ": other key", !verify(bcSig, pairs[1 - p].getPublicKey(), true, DATA));
            }
        }

        testSecretKeyProtection(label, bcKp);
    }

    private PGPDataEncryptorBuilder encryptorBuilder(boolean bc, int symmetricAlgorithm, boolean aead)
        throws PGPException
    {
        if (bc)
        {
            BcPGPDataEncryptorBuilder b = new BcPGPDataEncryptorBuilder(symmetricAlgorithm);
            if (aead)
            {
                // v2 SEIPD (RFC 9580), not the LibrePGP OCB packet the builder defaults to
                b.setWithAEAD(AEADAlgorithmTags.OCB, 6).setUseV6AEAD();
            }
            else
            {
                b.setWithIntegrityPacket(true);
            }
            return b;
        }
        JcePGPDataEncryptorBuilder b = new JcePGPDataEncryptorBuilder(symmetricAlgorithm).setProvider("BC");
        if (aead)
        {
            b.setWithAEAD(AEADAlgorithmTags.OCB, 6).setUseV6AEAD();
        }
        else
        {
            b.setWithIntegrityPacket(true);
        }
        return b;
    }

    private byte[] encrypt(PGPPublicKey recipient, boolean bc, int symmetricAlgorithm, boolean aead, byte[] data)
        throws PGPException, IOException
    {
        PGPEncryptedDataGenerator encGen = new PGPEncryptedDataGenerator(encryptorBuilder(bc, symmetricAlgorithm, aead));
        PublicKeyKeyEncryptionMethodGenerator metGen = bc
            ? (PublicKeyKeyEncryptionMethodGenerator)new BcPublicKeyKeyEncryptionMethodGenerator(recipient)
            : new JcePublicKeyKeyEncryptionMethodGenerator(recipient).setProvider("BC");
        encGen.addMethod(metGen);

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        OutputStream encOut = encGen.open(bOut, new byte[4096]);
        PGPLiteralDataGenerator litGen = new PGPLiteralDataGenerator();
        OutputStream litOut = litGen.open(encOut, PGPLiteralData.BINARY, "", PGPLiteralData.NOW, new byte[4096]);
        litOut.write(data);
        litOut.close();
        encOut.close();
        return bOut.toByteArray();
    }

    private PublicKeyDataDecryptorFactory decryptor(PGPKeyPair keyPair, boolean bc)
        throws PGPException
    {
        return bc ? (PublicKeyDataDecryptorFactory)new BcPublicKeyDataDecryptorFactory(keyPair)
            : new JcePublicKeyDataDecryptorFactoryBuilder().setProvider("BC").build(keyPair.getPrivateKey());
    }

    private byte[] decrypt(byte[] message, PGPKeyPair keyPair, boolean bc, int expectedPkeskVersion)
        throws PGPException, IOException
    {
        PGPObjectFactory objFac = new BcPGPObjectFactory(message);
        PGPEncryptedDataList encList = (PGPEncryptedDataList)objFac.nextObject();
        PGPPublicKeyEncryptedData encData = (PGPPublicKeyEncryptedData)encList.get(0);
        isEquals("PKESK version: expected " + expectedPkeskVersion + " got " + encData.getVersion() + " (bc decrypt=" + bc
            + ", key version " + keyPair.getPublicKey().getVersion() + ")", expectedPkeskVersion, encData.getVersion());
        isEquals("PKESK algorithm", keyPair.getPublicKey().getAlgorithm(), encData.getAlgorithm());
        isTrue("PKESK recipient: key " + org.bouncycastle.util.encoders.Hex.toHexString(keyPair.getPublicKey().getFingerprint())
                + " id " + Long.toHexString(keyPair.getKeyID()) + ", pkesk v" + encData.getVersion() + " fp "
                + (encData.getKeyIdentifier().getFingerprint() == null ? "null" : org.bouncycastle.util.encoders.Hex.toHexString(encData.getKeyIdentifier().getFingerprint()))
                + " id " + Long.toHexString(encData.getKeyID()),
            Arrays.areEqual(keyPair.getPublicKey().getFingerprint(), encData.getKeyIdentifier().getFingerprint())
            || encData.getKeyID() == keyPair.getKeyID());

        InputStream clear = encData.getDataStream(decryptor(keyPair, bc));
        PGPLiteralData lit = (PGPLiteralData)new BcPGPObjectFactory(clear).nextObject();
        byte[] plain = Streams.readAll(lit.getDataStream());
        isTrue("integrity", encData.verify());
        return plain;
    }

    private void testEncryptionKeyPair(int algorithm, Date creationTime)
        throws Exception
    {
        String label = "encryption algorithm " + algorithm;
        PGPKeyPair bcKp = generate(bcGenerator(PublicKeyPacket.VERSION_6, creationTime), algorithm);
        PGPKeyPair jcaKp = generate(jcaGenerator(PublicKeyPacket.VERSION_6, creationTime), algorithm);

        isEquals(label + ": algorithm", algorithm, bcKp.getPublicKey().getAlgorithm());
        isTrue(label + ": encryption key", bcKp.getPublicKey().isEncryptionKey());
        isTrue(label + ": not a signing key", !PublicKeyUtils.isSigningAlgorithm(bcKp.getPublicKey().getAlgorithm()));
        isTrue(label + ": key material", bcKp.getPublicKey().getPublicKeyPacket().getKey() instanceof MLKEMCompositePublicBCPGKey);
        isTrue(label + ": key material", jcaKp.getPublicKey().getPublicKeyPacket().getKey() instanceof MLKEMCompositePublicBCPGKey);

        checkKeyPairEncodings(label + " bc->jca", bcKp, toJcaKeyPair((BcPGPKeyPair)bcKp));
        checkKeyPairEncodings(label + " jca->bc", jcaKp, toBcKeyPair((JcaPGPKeyPair)jcaKp));

        PGPKeyPair[] pairs = { bcKp, jcaKp };
        int[] ciphers = { SymmetricKeyAlgorithmTags.AES_256, SymmetricKeyAlgorithmTags.AES_128 };
        for (int p = 0; p != pairs.length; p++)
        {
            for (int c = 0; c != ciphers.length; c++)
            {
                // v6 PKESK with v2 SEIPD (AEAD), encrypted and decrypted by either operator set
                byte[] bcMsg = encrypt(pairs[p].getPublicKey(), true, ciphers[c], true, DATA);
                byte[] jceMsg = encrypt(pairs[p].getPublicKey(), false, ciphers[c], true, DATA);
                isTrue(label + ": bc enc / bc dec", Arrays.areEqual(DATA, decrypt(bcMsg, pairs[p], true, PublicKeyEncSessionPacket.VERSION_6)));
                isTrue(label + ": bc enc / jce dec", Arrays.areEqual(DATA, decrypt(bcMsg, pairs[p], false, PublicKeyEncSessionPacket.VERSION_6)));
                isTrue(label + ": jce enc / bc dec", Arrays.areEqual(DATA, decrypt(jceMsg, pairs[p], true, PublicKeyEncSessionPacket.VERSION_6)));
                isTrue(label + ": jce enc / jce dec", Arrays.areEqual(DATA, decrypt(jceMsg, pairs[p], false, PublicKeyEncSessionPacket.VERSION_6)));

                // the other key pair cannot decrypt
                PGPObjectFactory objFac = new BcPGPObjectFactory(bcMsg);
                PGPPublicKeyEncryptedData encData = (PGPPublicKeyEncryptedData)((PGPEncryptedDataList)objFac.nextObject()).get(0);
                for (int impl = 0; impl != 2; impl++)
                {
                    try
                    {
                        encData.getDataStream(decryptor(pairs[1 - p], impl == 0));
                        fail(label + ": decryption with the wrong key MUST fail");
                    }
                    catch (PGPException e)
                    {
                        // expected: AES key unwrap fails
                    }
                }
            }
        }

        testSecretKeyProtection(label, bcKp);
    }

    /**
     * ML-KEM-768+X25519 is allowed in v4 keys (RFC 9980 sec. 3.5), with a v3 PKESK and a v1 SEIPD as well as
     * a v6 PKESK and a v2 SEIPD (Appendix A.2).
     */
    private void testV4MLKEM768X25519(Date creationTime)
        throws Exception
    {
        String label = "v4 ML-KEM-768+X25519";
        PGPKeyPair bcKp = bcGenerator(PublicKeyPacket.VERSION_4, creationTime).generateMLKEM768X25519KeyPair();
        PGPKeyPair jcaKp = jcaGenerator(PublicKeyPacket.VERSION_4, creationTime).generateMLKEM768X25519KeyPair();
        isEquals(label + ": version", PublicKeyPacket.VERSION_4, bcKp.getPublicKey().getVersion());
        isEquals(label + ": v4 fingerprint length", 20, bcKp.getPublicKey().getFingerprint().length);
        checkKeyPairEncodings(label + " bc->jca", bcKp, toJcaKeyPair((BcPGPKeyPair)bcKp));
        checkKeyPairEncodings(label + " jca->bc", jcaKp, toBcKeyPair((JcaPGPKeyPair)jcaKp));

        PGPKeyPair[] pairs = { bcKp, jcaKp };
        int[] ciphers = { SymmetricKeyAlgorithmTags.AES_128, SymmetricKeyAlgorithmTags.AES_192, SymmetricKeyAlgorithmTags.AES_256 };
        for (int p = 0; p != pairs.length; p++)
        {
            for (int c = 0; c != ciphers.length; c++)
            {
                byte[] bcMsg = encrypt(pairs[p].getPublicKey(), true, ciphers[c], false, DATA);
                byte[] jceMsg = encrypt(pairs[p].getPublicKey(), false, ciphers[c], false, DATA);
                isTrue(label + ": v3 bc enc / bc dec", Arrays.areEqual(DATA, decrypt(bcMsg, pairs[p], true, PublicKeyEncSessionPacket.VERSION_3)));
                isTrue(label + ": v3 bc enc / jce dec", Arrays.areEqual(DATA, decrypt(bcMsg, pairs[p], false, PublicKeyEncSessionPacket.VERSION_3)));
                isTrue(label + ": v3 jce enc / bc dec", Arrays.areEqual(DATA, decrypt(jceMsg, pairs[p], true, PublicKeyEncSessionPacket.VERSION_3)));
                isTrue(label + ": v3 jce enc / jce dec", Arrays.areEqual(DATA, decrypt(jceMsg, pairs[p], false, PublicKeyEncSessionPacket.VERSION_3)));

                byte[] bcMsg6 = encrypt(pairs[p].getPublicKey(), true, ciphers[c], true, DATA);
                isTrue(label + ": v6 bc enc / jce dec", Arrays.areEqual(DATA, decrypt(bcMsg6, pairs[p], false, PublicKeyEncSessionPacket.VERSION_6)));
            }
        }
    }

    private void testV4KeyGenerationIsRejected(Date creationTime)
        throws Exception
    {
        int[] v6Only = { PublicKeyAlgorithmTags.MLDSA65_Ed25519, PublicKeyAlgorithmTags.MLDSA87_Ed448, PublicKeyAlgorithmTags.SLHDSA_SHAKE_128s,
            PublicKeyAlgorithmTags.SLHDSA_SHAKE_128f, PublicKeyAlgorithmTags.SLHDSA_SHAKE_256s, PublicKeyAlgorithmTags.MLKEM1024_X448 };
        for (int i = 0; i != v6Only.length; i++)
        {
            try
            {
                generate(bcGenerator(PublicKeyPacket.VERSION_4, creationTime), v6Only[i]);
                fail("v4 key generation MUST be rejected for algorithm " + v6Only[i]);
            }
            catch (PGPException e)
            {
                isTrue(e.getMessage(), e.getMessage().indexOf("RFC 9980 sec. 3.5") >= 0);
            }
            try
            {
                generate(jcaGenerator(PublicKeyPacket.VERSION_4, creationTime), v6Only[i]);
                fail("v4 key generation MUST be rejected for algorithm " + v6Only[i]);
            }
            catch (PGPException e)
            {
                isTrue(e.getMessage(), e.getMessage().indexOf("RFC 9980 sec. 3.5") >= 0);
            }
        }
    }

    /**
     * RFC 9980 sec. 5.3.1 and 6.2.1: a digest of at least 256 bits, on both the signing and the verifying side.
     */
    private void testSmallDigestsAreRejected(Date creationTime)
        throws Exception
    {
        PGPKeyPair kp = bcGenerator(PublicKeyPacket.VERSION_6, creationTime).generateMLDSA65Ed25519KeyPair();
        PGPKeyPair slh = bcGenerator(PublicKeyPacket.VERSION_6, creationTime).generateSLHDSAShake128fKeyPair();
        PGPKeyPair[] pairs = { kp, slh };
        int[] small = { HashAlgorithmTags.SHA224, HashAlgorithmTags.SHA3_224, HashAlgorithmTags.SHA1, HashAlgorithmTags.RIPEMD160 };
        for (int p = 0; p != pairs.length; p++)
        {
            for (int h = 0; h != small.length; h++)
            {
                for (int impl = 0; impl != 2; impl++)
                {
                    boolean bc = impl == 0;
                    try
                    {
                        signerBuilder(bc, pairs[p].getPublicKey().getAlgorithm(), small[h]).build(PGPSignature.BINARY_DOCUMENT, pairs[p].getPrivateKey());
                        fail("hash " + small[h] + " MUST be rejected for signing with algorithm " + pairs[p].getPublicKey().getAlgorithm());
                    }
                    catch (PGPException e)
                    {
                        isTrue(e.getMessage(), e.getMessage().indexOf("at least 256 bits") >= 0);
                    }
                    try
                    {
                        verifierProvider(bc).get(pairs[p].getPublicKey().getAlgorithm(), small[h]).build(pairs[p].getPublicKey());
                        fail("hash " + small[h] + " MUST be rejected for verification with algorithm " + pairs[p].getPublicKey().getAlgorithm());
                    }
                    catch (PGPException e)
                    {
                        isTrue(e.getMessage(), e.getMessage().indexOf("at least 256 bits") >= 0);
                    }
                }
            }
        }

        // and through PGPSignature.init: a v6 signature packet naming SHA-224
        PGPSignature good = sign(kp, true, HashAlgorithmTags.SHA256, DATA);
        SignaturePacket packet = (SignaturePacket)new BCPGInputStream(new ByteArrayInputStream(good.getEncoded())).readPacket();
        SignaturePacket small224 = new SignaturePacket(packet.getVersion(), packet.getSignatureType(), packet.getKeyID(), packet.getKeyAlgorithm(),
            HashAlgorithmTags.SHA224, packet.getHashedSubPackets(), packet.getUnhashedSubPackets(), packet.getFingerPrint(),
            packet.getSignatureBytes(), packet.getSalt());
        try
        {
            toSignature(small224).init(new BcPGPContentVerifierBuilderProvider(), kp.getPublicKey());
            fail("SHA-224 composite signature MUST be rejected");
        }
        catch (PGPException e)
        {
            isTrue(e.getMessage(), e.getMessage().indexOf("at least 256 bits") >= 0);
        }
    }

    /**
     * RFC 9980 sec. 5.3.1 and 6.2.1: v6 signatures only.
     */
    private void testV4SignaturesAreRejected(Date creationTime)
        throws Exception
    {
        PGPKeyPair kp = bcGenerator(PublicKeyPacket.VERSION_6, creationTime).generateMLDSA65Ed25519KeyPair();
        // the key version check of the generator constructor is bypassed by not naming the signing key
        PGPSignatureGenerator sigGen = new PGPSignatureGenerator(
            new BcPGPContentSignerBuilder(PublicKeyAlgorithmTags.MLDSA65_Ed25519, HashAlgorithmTags.SHA512), (PGPPublicKey)null, SignaturePacket.VERSION_4);
        try
        {
            sigGen.init(PGPSignature.BINARY_DOCUMENT, kp.getPrivateKey());
            fail("v4 signature with ML-DSA-65+Ed25519 MUST be rejected");
        }
        catch (PGPException e)
        {
            isTrue(e.getMessage(), e.getMessage().indexOf("version 6 signatures") >= 0);
        }

        // a parsed v4 signature packet naming a PQ(/T) algorithm is rejected at verification: build the v4
        // packet by hand from the fields of a good v6 one (RFC 9580 sec. 5.2.3)
        PGPSignature good = sign(kp, true, HashAlgorithmTags.SHA256, DATA);
        SignaturePacket packet = (SignaturePacket)new BCPGInputStream(new ByteArrayInputStream(good.getEncoded())).readPacket();
        ByteArrayOutputStream hashed = new ByteArrayOutputStream();
        for (int i = 0; i != packet.getHashedSubPackets().length; i++)
        {
            packet.getHashedSubPackets()[i].encode(hashed);
        }
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        body.write(SignaturePacket.VERSION_4);
        body.write(packet.getSignatureType());
        body.write(packet.getKeyAlgorithm());
        body.write(packet.getHashAlgorithm());
        body.write(hashed.size() >>> 8);
        body.write(hashed.size());
        body.write(hashed.toByteArray());
        body.write(0);
        body.write(0);
        body.write(packet.getFingerPrint());
        body.write(packet.getSignatureBytes());
        byte[] v4Body = body.toByteArray();
        byte[] framed = Arrays.concatenate(new byte[]{ (byte)0xc2, (byte)0xff,
            (byte)(v4Body.length >>> 24), (byte)(v4Body.length >>> 16), (byte)(v4Body.length >>> 8), (byte)v4Body.length }, v4Body);
        PGPSignature v4 = new PGPSignature(new BCPGInputStream(new ByteArrayInputStream(framed)));
        isEquals("v4 signature parsed", SignaturePacket.VERSION_4, v4.getVersion());
        isEquals("v4 signature algorithm", PublicKeyAlgorithmTags.MLDSA65_Ed25519, v4.getKeyAlgorithm());
        PGPKeyPair v4Key = bcGenerator(PublicKeyPacket.VERSION_4, creationTime).generateMLKEM768X25519KeyPair();
        try
        {
            v4.init(new BcPGPContentVerifierBuilderProvider(), v4Key.getPublicKey());
            fail("v4 signature with a PQ(/T) algorithm MUST be rejected");
        }
        catch (PGPException e)
        {
            isTrue(e.getMessage(), e.getMessage().indexOf("version 6 signatures") >= 0);
        }
    }

    private PGPSignature withSignatureBytes(PGPSignature sig, byte[] signatureBytes)
        throws IOException, PGPException
    {
        SignaturePacket packet = (SignaturePacket)new BCPGInputStream(new ByteArrayInputStream(sig.getEncoded())).readPacket();
        return toSignature(new SignaturePacket(packet.getVersion(), packet.getSignatureType(), packet.getKeyID(), packet.getKeyAlgorithm(),
            packet.getHashAlgorithm(), packet.getHashedSubPackets(), packet.getUnhashedSubPackets(), packet.getFingerPrint(),
            signatureBytes, packet.getSalt()));
    }

    private static PGPSignature toSignature(SignaturePacket packet)
        throws IOException, PGPException
    {
        return new PGPSignature(new BCPGInputStream(new ByteArrayInputStream(packet.getEncoded())));
    }

    /**
     * RFC 9980 sec. 5.2.3: both component signatures MUST verify. A flipped bit in either component, a
     * truncated or an extended signature all fail, with either verifier.
     */
    private void testCorruptedCompositeSignature(Date creationTime)
        throws Exception
    {
        int[] algs = { PublicKeyAlgorithmTags.MLDSA65_Ed25519, PublicKeyAlgorithmTags.MLDSA87_Ed448 };
        for (int a = 0; a != algs.length; a++)
        {
            PGPKeyPair kp = generate(bcGenerator(PublicKeyPacket.VERSION_6, creationTime), algs[a]);
            PGPSignature good = sign(kp, true, HashAlgorithmTags.SHA512, DATA);
            byte[] sigBytes = good.getSignature();
            int eddsaLen = MLDSACompositePublicBCPGKey.getEdDSASignatureLength(algs[a]);

            byte[] eddsaFlipped = Arrays.clone(sigBytes);
            eddsaFlipped[eddsaLen / 2] ^= 0x01;
            byte[] mldsaFlipped = Arrays.clone(sigBytes);
            mldsaFlipped[eddsaLen + 100] ^= 0x01;
            byte[] swapped = Arrays.concatenate(Arrays.copyOfRange(sigBytes, eddsaLen, sigBytes.length), Arrays.copyOf(sigBytes, eddsaLen));
            byte[][] bad = { eddsaFlipped, mldsaFlipped, swapped };
            String[] names = { "EdDSA component flipped", "ML-DSA component flipped", "components swapped" };

            for (int impl = 0; impl != 2; impl++)
            {
                boolean bc = impl == 0;
                isTrue("sanity", verify(withSignatureBytes(good, sigBytes), kp.getPublicKey(), bc, DATA));
                for (int i = 0; i != bad.length; i++)
                {
                    isTrue(names[i] + " MUST NOT verify (" + (bc ? "bc" : "jca") + ")", !verify(withSignatureBytes(good, bad[i]), kp.getPublicKey(), bc, DATA));
                }
                // the verifiers answer false, not an exception, for a wrong-length signature value
                isTrue("truncated MUST NOT verify", !verifyRaw(kp.getPublicKey(), bc, HashAlgorithmTags.SHA512, Arrays.copyOf(sigBytes, sigBytes.length - 1)));
                isTrue("extended MUST NOT verify", !verifyRaw(kp.getPublicKey(), bc, HashAlgorithmTags.SHA512, Arrays.append(sigBytes, (byte)0)));
                isTrue("empty MUST NOT verify", !verifyRaw(kp.getPublicKey(), bc, HashAlgorithmTags.SHA512, new byte[0]));
            }
        }

        // SLH-DSA: a flipped bit, with either verifier
        PGPKeyPair slh = bcGenerator(PublicKeyPacket.VERSION_6, creationTime).generateSLHDSAShake128fKeyPair();
        PGPSignature good = sign(slh, false, HashAlgorithmTags.SHA256, DATA);
        byte[] flipped = good.getSignature();
        flipped[flipped.length / 2] ^= 0x01;
        for (int impl = 0; impl != 2; impl++)
        {
            boolean bc = impl == 0;
            isTrue("SLH-DSA flipped MUST NOT verify", !verify(withSignatureBytes(good, flipped), slh.getPublicKey(), bc, DATA));
            isTrue("SLH-DSA truncated MUST NOT verify", !verifyRaw(slh.getPublicKey(), bc, HashAlgorithmTags.SHA256, Arrays.copyOf(flipped, flipped.length - 1)));
        }
    }

    private boolean verifyRaw(PGPPublicKey publicKey, boolean bc, int hashAlgorithm, byte[] signature)
        throws Exception
    {
        org.bouncycastle.openpgp.operator.PGPContentVerifier verifier = verifierProvider(bc).get(publicKey.getAlgorithm(), hashAlgorithm).build(publicKey);
        OutputStream out = verifier.getOutputStream();
        out.write(DATA);
        out.close();
        return verifier.verify(signature);
    }

    /**
     * RFC 9980 sec. 4.3.1: a v3 PKESK packet MUST use AES-128, AES-192 or AES-256.
     */
    private void testV3PKESKRequiresAES(Date creationTime)
        throws Exception
    {
        PGPKeyPair kp = bcGenerator(PublicKeyPacket.VERSION_4, creationTime).generateMLKEM768X25519KeyPair();
        int[] nonAES = { SymmetricKeyAlgorithmTags.CAMELLIA_256, SymmetricKeyAlgorithmTags.TWOFISH };
        for (int c = 0; c != nonAES.length; c++)
        {
            for (int impl = 0; impl != 2; impl++)
            {
                try
                {
                    encrypt(kp.getPublicKey(), impl == 0, nonAES[c], false, DATA);
                    fail("v3 PKESK with symmetric algorithm " + nonAES[c] + " MUST be rejected");
                }
                catch (PGPException e)
                {
                    isTrue(e.getMessage(), e.getMessage().indexOf("AES-128, AES-192 or AES-256") >= 0);
                }
            }
        }
    }

    /**
     * RFC 9980 sec. 4.3.1: the receiver MUST check that the unwrapped session key length matches the symmetric
     * algorithm octet of a v3 PKESK packet.
     */
    private void testTamperedV3SymmetricAlgorithmOctet(Date creationTime)
        throws Exception
    {
        PGPKeyPair kp = bcGenerator(PublicKeyPacket.VERSION_4, creationTime).generateMLKEM768X25519KeyPair();
        byte[] message = encrypt(kp.getPublicKey(), true, SymmetricKeyAlgorithmTags.AES_256, false, DATA);
        PublicKeyEncSessionPacket pkesk = (PublicKeyEncSessionPacket)new BCPGInputStream(new ByteArrayInputStream(message)).readPacket();
        byte[] data = pkesk.getEncSessionKey()[0];
        int offset = MLKEMCompositePublicBCPGKey.getECDHPublicKeyLength(PublicKeyAlgorithmTags.MLKEM768_X25519)
            + MLKEMCompositePublicBCPGKey.getMLKEMCiphertextLength(PublicKeyAlgorithmTags.MLKEM768_X25519) + 1;
        isEquals("symmetric algorithm octet", SymmetricKeyAlgorithmTags.AES_256, data[offset] & 0xff);

        for (int impl = 0; impl != 2; impl++)
        {
            PublicKeyDataDecryptorFactory dec = decryptor(kp, impl == 0);
            byte[] sessionData = dec.recoverSessionData(PublicKeyAlgorithmTags.MLKEM768_X25519, new byte[][]{ data }, PublicKeyEncSessionPacket.VERSION_3);
            isEquals("session key length", 32, sessionData.length);

            byte[] tampered = Arrays.clone(data);
            tampered[offset] = (byte)SymmetricKeyAlgorithmTags.AES_128;
            try
            {
                dec.recoverSessionData(PublicKeyAlgorithmTags.MLKEM768_X25519, new byte[][]{ tampered }, PublicKeyEncSessionPacket.VERSION_3);
                fail("session key length mismatch MUST be rejected");
            }
            catch (PGPException e)
            {
                isTrue(e.getMessage(), e.getMessage().indexOf("does not match symmetric algorithm") >= 0);
            }

            tampered[offset] = (byte)SymmetricKeyAlgorithmTags.CAMELLIA_256;
            try
            {
                dec.recoverSessionData(PublicKeyAlgorithmTags.MLKEM768_X25519, new byte[][]{ tampered }, PublicKeyEncSessionPacket.VERSION_3);
                fail("non-AES symmetric algorithm MUST be rejected");
            }
            catch (PGPException e)
            {
                isTrue(e.getMessage(), e.getMessage().indexOf("AES-128, AES-192 or AES-256") >= 0);
            }
        }
    }

    private void testTruncatedPKESKIsRejected(Date creationTime)
        throws Exception
    {
        PGPKeyPair kp = bcGenerator(PublicKeyPacket.VERSION_6, creationTime).generateMLKEM1024X448KeyPair();
        byte[] message = encrypt(kp.getPublicKey(), true, SymmetricKeyAlgorithmTags.AES_256, true, DATA);
        PublicKeyEncSessionPacket pkesk = (PublicKeyEncSessionPacket)new BCPGInputStream(new ByteArrayInputStream(message)).readPacket();
        byte[] data = pkesk.getEncSessionKey()[0];
        int[] lengths = { 0, 10, 56, 56 + 1568, 56 + 1568 + 1, data.length - 1 };
        for (int impl = 0; impl != 2; impl++)
        {
            PublicKeyDataDecryptorFactory dec = decryptor(kp, impl == 0);
            for (int i = 0; i != lengths.length; i++)
            {
                try
                {
                    dec.recoverSessionData(PublicKeyAlgorithmTags.MLKEM1024_X448, new byte[][]{ Arrays.copyOf(data, lengths[i]) }, PublicKeyEncSessionPacket.VERSION_6);
                    fail("truncated PKESK data (" + lengths[i] + " octets) MUST be rejected");
                }
                catch (PGPException e)
                {
                    // expected
                }
            }
            // the right algorithm with the wrong key
            try
            {
                dec.recoverSessionData(PublicKeyAlgorithmTags.MLKEM768_X25519, new byte[][]{ data }, PublicKeyEncSessionPacket.VERSION_6);
                fail("algorithm mismatch MUST be rejected");
            }
            catch (PGPException e)
            {
                isTrue(e.getMessage(), e.getMessage().indexOf("does not match") >= 0);
            }
        }
    }

    /**
     * RFC 9980 sec. 7.2: a subkey binding signature over a PQ(/T) key made with MD5, SHA-1 or RIPEMD-160 is
     * invalid. Only a v4 primary can make such a signature at all.
     */
    private void testBindingSignatureHashRule(Date creationTime)
        throws Exception
    {
        PGPKeyPair primary = bcGenerator(PublicKeyPacket.VERSION_4, creationTime).generateEd25519KeyPair();
        PGPKeyPair subkey = bcGenerator(PublicKeyPacket.VERSION_4, creationTime).generateMLKEM768X25519KeyPair()
            .asSubkey(new BcKeyFingerprintCalculator());
        PGPKeyPair x25519 = bcGenerator(PublicKeyPacket.VERSION_4, creationTime).generateX25519KeyPair()
            .asSubkey(new BcKeyFingerprintCalculator());

        int[] hashes = { HashAlgorithmTags.SHA1, HashAlgorithmTags.RIPEMD160, HashAlgorithmTags.SHA256 };
        for (int h = 0; h != hashes.length; h++)
        {
            PGPSignatureGenerator sigGen = new PGPSignatureGenerator(
                new BcPGPContentSignerBuilder(PublicKeyAlgorithmTags.Ed25519, hashes[h]), primary.getPublicKey());
            sigGen.init(PGPSignature.SUBKEY_BINDING, primary.getPrivateKey());
            PGPSignature binding = sigGen.generateCertification(primary.getPublicKey(), subkey.getPublicKey());
            binding.init(new BcPGPContentVerifierBuilderProvider(), primary.getPublicKey());
            boolean valid = binding.verifyCertification(primary.getPublicKey(), subkey.getPublicKey());
            isEquals("binding of an ML-KEM subkey with hash " + hashes[h], hashes[h] == HashAlgorithmTags.SHA256, valid);

            // the rule is about PQ(/T) subkeys only
            sigGen = new PGPSignatureGenerator(new BcPGPContentSignerBuilder(PublicKeyAlgorithmTags.Ed25519, hashes[h]), primary.getPublicKey());
            sigGen.init(PGPSignature.SUBKEY_BINDING, primary.getPrivateKey());
            PGPSignature classic = sigGen.generateCertification(primary.getPublicKey(), x25519.getPublicKey());
            classic.init(new BcPGPContentVerifierBuilderProvider(), primary.getPublicKey());
            isTrue("binding of an X25519 subkey with hash " + hashes[h], classic.verifyCertification(primary.getPublicKey(), x25519.getPublicKey()));
        }
    }

    private void testSecretKeyProtection(String label, PGPKeyPair keyPair)
        throws Exception
    {
        // an encryption-only key is always stored as a subkey, and the AEAD protection binds the key packet
        // (tag included) as associated data - so take the subkey form before building the encryptor
        if (keyPair.getPublicKey().isEncryptionKey())
        {
            keyPair = keyPair.asSubkey(new BcKeyFingerprintCalculator());
        }
        PGPDigestCalculatorProvider digestProv = new BcPGPDigestCalculatorProvider();
        BcAEADSecretKeyEncryptorBuilder encBuilder = new BcAEADSecretKeyEncryptorBuilder(
            AEADAlgorithmTags.OCB, SymmetricKeyAlgorithmTags.AES_256, S2K.Argon2Params.memoryConstrainedParameters());
        PGPSecretKey sk = new PGPSecretKey(keyPair.getPrivateKey(), keyPair.getPublicKey(), digestProv.get(HashAlgorithmTags.SHA1),
            !keyPair.getPublicKey().isEncryptionKey(), encBuilder.build("passphrase".toCharArray(), keyPair.getPublicKey().getPublicKeyPacket()));

        // through the encoding
        PGPSecretKey parsed = new PGPSecretKey(
            (org.bouncycastle.bcpg.SecretKeyPacket)new BCPGInputStream(new ByteArrayInputStream(sk.getEncoded())).readPacket(),
            keyPair.getPublicKey());
        PGPPrivateKey bcPriv = parsed.extractPrivateKey(new BcPBESecretKeyDecryptorBuilder(digestProv).build("passphrase".toCharArray()));
        PGPPrivateKey jcePriv = parsed.extractPrivateKey(new JcePBESecretKeyDecryptorBuilder().setProvider("BC").build("passphrase".toCharArray()));
        byte[] expected = keyPair.getPrivateKey().getPrivateKeyDataPacket().getEncoded();
        isTrue(label + ": AEAD-protected key recovered (bc)", Arrays.areEqual(expected, bcPriv.getPrivateKeyDataPacket().getEncoded()));
        isTrue(label + ": AEAD-protected key recovered (jce)", Arrays.areEqual(expected, jcePriv.getPrivateKeyDataPacket().getEncoded()));
        try
        {
            parsed.extractPrivateKey(new BcPBESecretKeyDecryptorBuilder(digestProv).build("password".toCharArray()));
            fail(label + ": wrong passphrase MUST fail");
        }
        catch (PGPException e)
        {
            // expected
        }

        // an unprotected secret key
        PGPSecretKey plain = new PGPSecretKey(keyPair.getPrivateKey(), keyPair.getPublicKey(), digestProv.get(HashAlgorithmTags.SHA1),
            !keyPair.getPublicKey().isEncryptionKey(), null);
        PGPSecretKey plainParsed = new PGPSecretKey(
            (org.bouncycastle.bcpg.SecretKeyPacket)new BCPGInputStream(new ByteArrayInputStream(plain.getEncoded())).readPacket(),
            keyPair.getPublicKey());
        isTrue(label + ": unprotected key recovered",
            Arrays.areEqual(expected, plainParsed.extractPrivateKey(null).getPrivateKeyDataPacket().getEncoded()));
    }

    public static void main(String[] args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new PGPRFC9980KeyPairTest());
    }
}
