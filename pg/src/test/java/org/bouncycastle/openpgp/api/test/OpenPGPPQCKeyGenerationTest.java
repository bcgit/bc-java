package org.bouncycastle.openpgp.api.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.Date;
import java.util.List;

import org.bouncycastle.bcpg.AEADAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyPacket;
import org.bouncycastle.bcpg.SignatureSubpacketTags;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.bcpg.sig.Features;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.bouncycastle.openpgp.api.EncryptedDataPacketType;
import org.bouncycastle.openpgp.api.KeyPairGeneratorCallback;
import org.bouncycastle.openpgp.api.MessageEncryptionMechanism;
import org.bouncycastle.openpgp.api.OpenPGPApi;
import org.bouncycastle.openpgp.api.OpenPGPCertificate;
import org.bouncycastle.openpgp.api.OpenPGPKey;
import org.bouncycastle.openpgp.api.OpenPGPKeyGenerator;
import org.bouncycastle.openpgp.api.OpenPGPMessageGenerator;
import org.bouncycastle.openpgp.api.OpenPGPMessageInputStream;
import org.bouncycastle.openpgp.api.OpenPGPMessageProcessor;
import org.bouncycastle.openpgp.api.OpenPGPSignature;
import org.bouncycastle.openpgp.api.SignatureParameters;
import org.bouncycastle.openpgp.api.SignatureSubpacketsFunction;
import org.bouncycastle.openpgp.operator.PGPKeyPairGenerator;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.io.Streams;

/**
 * The RFC 9980 key profiles of the high-level API: each profile yields a v6 key with the expected algorithms
 * whose certificate encrypts, decrypts, signs and verifies messages and detached signatures, under both the
 * Bc and the Jca implementation; v4 generation is refused; and a certificate with a PQ(/T) key implicitly
 * prefers AES-256 (RFC 9980 sec. 7.1) when its explicit preferences are unusable.
 */
public class OpenPGPPQCKeyGenerationTest
    extends APITest
{
    private static final byte[] PLAINTEXT = Strings.toUTF8ByteArray("Hello, World!\n");

    @Override
    public String getName()
    {
        return "OpenPGPPQCKeyGenerationTest";
    }

    @Override
    protected void performTestWith(OpenPGPApi api)
        throws PGPException, IOException
    {
        Date creationTime = currentTimeRounded();

        testProfile(api, api.generateKey(creationTime).mlDsa65Ed25519MlKem768X25519Key("Alice <alice@example.org>").build(),
            PublicKeyAlgorithmTags.MLDSA65_Ed25519, PublicKeyAlgorithmTags.MLKEM768_X25519, creationTime);
        testProfile(api, api.generateKey(creationTime).mlDsa87Ed448MlKem1024X448Key("Bob <bob@example.org>").build(),
            PublicKeyAlgorithmTags.MLDSA87_Ed448, PublicKeyAlgorithmTags.MLKEM1024_X448, creationTime);
        testProfile(api, api.generateKey(creationTime).slhDsaShake128fMlKem768X25519Key("Carol <carol@example.org>").build(),
            PublicKeyAlgorithmTags.SLHDSA_SHAKE_128f, PublicKeyAlgorithmTags.MLKEM768_X25519, creationTime);
        // the "s" parameter sets sign slowly; one is enough to cover the profile wiring
        testProfile(api, api.generateKey(creationTime).slhDsaShake128sMlKem768X25519Key(null).build(),
            PublicKeyAlgorithmTags.SLHDSA_SHAKE_128s, PublicKeyAlgorithmTags.MLKEM768_X25519, creationTime);

        testV4GenerationIsRejected(api);
        testPQCCertificateImplicitlyPrefersAES256(api, creationTime);
    }

    private void testProfile(OpenPGPApi api, OpenPGPKey key, int signingAlgorithm, int kemAlgorithm, Date creationTime)
        throws PGPException, IOException
    {
        String label = "profile " + signingAlgorithm + "/" + kemAlgorithm;
        OpenPGPCertificate.OpenPGPPrimaryKey primaryKey = key.getPrimaryKey();
        isEquals(label + ": primary key version", PublicKeyPacket.VERSION_6, primaryKey.getPGPPublicKey().getVersion());
        isEquals(label + ": primary key algorithm", signingAlgorithm, primaryKey.getAlgorithm());
        isEquals(label + ": creation time", creationTime, primaryKey.getCreationTime());
        isTrue(label + ": primary key certifies", primaryKey.isCertificationKey());
        isTrue(label + ": primary key does not sign data", !primaryKey.isSigningKey());

        List<OpenPGPCertificate.OpenPGPComponentKey> signingKeys = key.getSigningKeys();
        isEquals(label + ": one signing subkey", 1, signingKeys.size());
        isEquals(label + ": signing subkey algorithm", signingAlgorithm, signingKeys.get(0).getAlgorithm());
        isEquals(label + ": signing subkey version", PublicKeyPacket.VERSION_6, signingKeys.get(0).getPGPPublicKey().getVersion());

        List<OpenPGPCertificate.OpenPGPComponentKey> encryptionKeys = key.getEncryptionKeys();
        isEquals(label + ": one encryption subkey", 1, encryptionKeys.size());
        isEquals(label + ": encryption subkey algorithm", kemAlgorithm, encryptionKeys.get(0).getAlgorithm());

        // the certificate round-trips through its encoding and is still fully bound
        OpenPGPCertificate cert = api.readKeyOrCertificate().parseCertificate(key.toCertificate().getEncoded());
        isEquals(label + ": parsed certificate signing keys", 1, cert.getSigningKeys().size());
        isEquals(label + ": parsed certificate encryption keys", 1, cert.getEncryptionKeys().size());
        OpenPGPKey parsedKey = api.readKeyOrCertificate().parseKey(key.getEncoded());
        isEquals(label + ": parsed key secret keys", 3, parsedKey.getSecretKeys().size());

        // encrypt and sign for the certificate, decrypt and verify with the key
        OpenPGPMessageGenerator gen = api.signAndOrEncryptMessage()
            .setArmored(true)
            .addEncryptionCertificate(cert)
            .addSigningKey(key)
            .setAllowPadding(false);
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        OutputStream msgOut = gen.open(bOut);
        msgOut.write(PLAINTEXT);
        msgOut.close();

        OpenPGPMessageProcessor processor = api.decryptAndOrVerifyMessage()
            .addDecryptionKey(parsedKey)
            .addVerificationCertificate(cert);
        OpenPGPMessageInputStream plainIn = processor.process(new ByteArrayInputStream(bOut.toByteArray()));
        ByteArrayOutputStream plainOut = new ByteArrayOutputStream();
        Streams.pipeAll(plainIn, plainOut);
        plainIn.close();
        isEncodingEqual(label + ": plaintext", PLAINTEXT, plainOut.toByteArray());

        OpenPGPMessageInputStream.Result result = plainIn.getResult();
        isEquals(label + ": decryption key", kemAlgorithm, result.getDecryptionKey().getAlgorithm());
        isEquals(label + ": AES-256 negotiated for a PQ(/T) certificate (RFC 9980 sec. 7.1)",
            SymmetricKeyAlgorithmTags.AES_256, result.getEncryptionMethod().getSymmetricKeyAlgorithm());
        isEquals(label + ": AES-256 with OCB", AEADAlgorithmTags.OCB, result.getEncryptionMethod().getAeadAlgorithm());
        List<OpenPGPSignature.OpenPGPDocumentSignature> signatures = result.getSignatures();
        isEquals(label + ": one signature", 1, signatures.size());
        isTrue(label + ": signature valid", signatures.get(0).isValid());
        isEquals(label + ": signature algorithm", signingAlgorithm, signatures.get(0).getSignature().getKeyAlgorithm());
        isEquals(label + ": signature version", 6, signatures.get(0).getSignature().getVersion());

        // a detached signature
        List<OpenPGPSignature.OpenPGPDocumentSignature> detached = api.createDetachedSignature()
            .addSigningKey(key)
            .sign(new ByteArrayInputStream(PLAINTEXT));
        isEquals(label + ": one detached signature", 1, detached.size());
        List<OpenPGPSignature.OpenPGPDocumentSignature> verified = api.verifyDetachedSignature()
            .addSignatures(new ByteArrayInputStream(detached.get(0).getSignature().getEncoded()))
            .addVerificationCertificate(cert)
            .process(new ByteArrayInputStream(PLAINTEXT));
        isEquals(label + ": detached signature verified", 1, verified.size());
        isTrue(label + ": detached signature valid", verified.get(0).isValid());
    }

    private void testV4GenerationIsRejected(OpenPGPApi api)
        throws IOException
    {
        try
        {
            api.generateKey(PublicKeyPacket.VERSION_4).mlDsa65Ed25519MlKem768X25519Key("v4").build();
            fail("v4 ML-DSA-65+Ed25519 key MUST NOT be generated");
        }
        catch (PGPException e)
        {
            isTrue(e.getMessage(), e.getMessage().indexOf("RFC 9980 sec. 3.5") >= 0);
        }
        try
        {
            api.generateKey(PublicKeyPacket.VERSION_4).slhDsaShake256sMlKem1024X448Key("v4").build();
            fail("v4 SLH-DSA key MUST NOT be generated");
        }
        catch (PGPException e)
        {
            isTrue(e.getMessage(), e.getMessage().indexOf("RFC 9980 sec. 3.5") >= 0);
        }
    }

    /**
     * RFC 9980 sec. 7.1: if AES-256 is not in a certificate's preferences and the certificate contains a
     * PQ(/T) key, it is implicitly at the end of the list. With an explicit preference the policy rejects,
     * a PQ(/T) certificate therefore gets AES-256 where a traditional one falls back to AES-128. The
     * certificates announce only the v1 SEIPD feature here, because the AEAD ciphersuite subpacket always
     * carries the mandatory AES-128 with OCB explicitly and so never has an unusable explicit list.
     */
    private void testPQCCertificateImplicitlyPrefersAES256(OpenPGPApi api, Date creationTime)
        throws PGPException, IOException
    {
        SignatureParameters.Callback ideaOnly = SignatureParameters.Callback.Util.modifyHashedSubpackets(new SignatureSubpacketsFunction()
        {
            @Override
            public PGPSignatureSubpacketGenerator apply(PGPSignatureSubpacketGenerator subpackets)
            {
                subpackets.removePacketsOfType(SignatureSubpacketTags.PREFERRED_SYM_ALGS);
                subpackets.setPreferredSymmetricAlgorithms(false, new int[]{ SymmetricKeyAlgorithmTags.IDEA });
                subpackets.removePacketsOfType(SignatureSubpacketTags.FEATURES);
                subpackets.setFeature(false, Features.FEATURE_MODIFICATION_DETECTION);
                return subpackets;
            }
        });

        OpenPGPKey pqcKey = api.generateKey(creationTime)
            .withPrimaryKey(new KeyPairGeneratorCallback()
            {
                public PGPKeyPair generateFrom(PGPKeyPairGenerator generator)
                    throws PGPException
                {
                    return generator.generateMLDSA65Ed25519KeyPair();
                }
            }, ideaOnly)
            .addEncryptionSubkey(new KeyPairGeneratorCallback()
            {
                public PGPKeyPair generateFrom(PGPKeyPairGenerator generator)
                    throws PGPException
                {
                    return generator.generateMLKEM768X25519KeyPair();
                }
            })
            .build();
        OpenPGPKey classicKey = api.generateKey(creationTime)
            .withPrimaryKey(new KeyPairGeneratorCallback()
            {
                public PGPKeyPair generateFrom(PGPKeyPairGenerator generator)
                    throws PGPException
                {
                    return generator.generateEd25519KeyPair();
                }
            }, ideaOnly)
            .addEncryptionSubkey(new KeyPairGeneratorCallback()
            {
                public PGPKeyPair generateFrom(PGPKeyPairGenerator generator)
                    throws PGPException
                {
                    return generator.generateX25519KeyPair();
                }
            })
            .build();

        MessageEncryptionMechanism pqc = negotiatedMechanism(api, pqcKey);
        isEquals("PQ(/T) certificate with unusable explicit preferences negotiates the implicit AES-256",
            SymmetricKeyAlgorithmTags.AES_256, pqc.getSymmetricKeyAlgorithm());
        isEquals("v1 SEIPD", EncryptedDataPacketType.SEIPDv1, pqc.getMode());
        MessageEncryptionMechanism classic = negotiatedMechanism(api, classicKey);
        isEquals("traditional certificate with unusable explicit preferences falls back to the default",
            SymmetricKeyAlgorithmTags.AES_128, classic.getSymmetricKeyAlgorithm());
    }

    private MessageEncryptionMechanism negotiatedMechanism(OpenPGPApi api, OpenPGPKey key)
        throws PGPException, IOException
    {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        OutputStream msgOut = api.signAndOrEncryptMessage()
            .addEncryptionCertificate(key.toCertificate())
            .setAllowPadding(false)
            .open(bOut);
        msgOut.write(PLAINTEXT);
        msgOut.close();

        OpenPGPMessageInputStream plainIn = api.decryptAndOrVerifyMessage()
            .addDecryptionKey(key)
            .process(new ByteArrayInputStream(bOut.toByteArray()));
        ByteArrayOutputStream plainOut = new ByteArrayOutputStream();
        Streams.pipeAll(plainIn, plainOut);
        plainIn.close();
        isEncodingEqual(PLAINTEXT, plainOut.toByteArray());
        return plainIn.getResult().getEncryptionMethod();
    }

    public static void main(String[] args)
    {
        runTest(new OpenPGPPQCKeyGenerationTest());
    }
}
