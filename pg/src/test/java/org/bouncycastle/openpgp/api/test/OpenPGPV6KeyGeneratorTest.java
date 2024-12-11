package org.bouncycastle.openpgp.api.test;

import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyPacket;
import org.bouncycastle.bcpg.PublicKeyUtils;
import org.bouncycastle.bcpg.SecretKeyPacket;
import org.bouncycastle.bcpg.SignaturePacket;
import org.bouncycastle.bcpg.SignatureSubpacketTags;
import org.bouncycastle.bcpg.sig.Features;
import org.bouncycastle.bcpg.sig.KeyFlags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureSubpacketVector;
import org.bouncycastle.openpgp.api.KeyPairGeneratorCallback;
import org.bouncycastle.openpgp.api.OpenPGPV6KeyGenerator;
import org.bouncycastle.openpgp.api.bc.BcOpenPGPV6KeyGenerator;
import org.bouncycastle.openpgp.api.jcajce.JcaOpenPGPV6KeyGenerator;
import org.bouncycastle.openpgp.operator.PGPKeyPairGenerator;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.bc.BcPGPKeyPairGeneratorProvider;
import org.bouncycastle.openpgp.test.AbstractPgpKeyPairTest;

import java.io.IOException;
import java.util.Date;
import java.util.Iterator;

public class OpenPGPV6KeyGeneratorTest
        extends AbstractPgpKeyPairTest
{
    @Override
    public String getName()
    {
        return "OpenPGPV6KeyGeneratorTest";
    }

    @Override
    public void performTest()
            throws Exception
    {
        // Run tests using the BC implementation
        performTests(new APIProvider()
        {
            @Override
            public OpenPGPV6KeyGenerator getKeyGenerator(int signatureHashAlgorithm,
                                                         Date creationTime,
                                                         boolean aeadProtection)
            {
                return new BcOpenPGPV6KeyGenerator(signatureHashAlgorithm, creationTime, aeadProtection);
            }
        });

        // Run tests using the JCA/JCE implementation
        performTests(new APIProvider()
        {
            @Override
            public OpenPGPV6KeyGenerator getKeyGenerator(int signatureHashAlgorithm,
                                                         Date creationTime,
                                                         boolean aeadProtection)
                    throws PGPException
            {
                return new JcaOpenPGPV6KeyGenerator(signatureHashAlgorithm, creationTime, aeadProtection,
                        new BouncyCastleProvider());
            }
        });
    }

    private void performTests(APIProvider apiProvider)
            throws PGPException, IOException
    {
        testGenerateCustomKey(apiProvider);

        testGenerateSignOnlyKeyBaseCase(apiProvider);
        testGenerateAEADProtectedSignOnlyKey(apiProvider);
        testGenerateCFBProtectedSignOnlyKey(apiProvider);

        testGenerateClassicKeyBaseCase(apiProvider);
        testGenerateProtectedTypicalKey(apiProvider);

        testGenerateEd25519x25519Key(apiProvider);
        testGenerateEd448x448Key(apiProvider);

        testEnforcesPrimaryOrSubkeyType(apiProvider);
    }

    private void testGenerateSignOnlyKeyBaseCase(APIProvider apiProvider)
            throws PGPException
    {
        OpenPGPV6KeyGenerator generator = apiProvider.getKeyGenerator();
        PGPSecretKeyRing secretKeys = generator.signOnlyKey(null);

        Iterator<PGPSecretKey> it = secretKeys.getSecretKeys();
        PGPSecretKey primaryKey = it.next();
        isFalse("sign-only key MUST consists of only a single key", it.hasNext());
        PGPSignature directKeySignature = primaryKey.getPublicKey().getKeySignatures().next();
        isNotNull("Key MUST have direct-key signature", directKeySignature);
        isEquals("Direct-key signature MUST be version 6",
                SignaturePacket.VERSION_6, directKeySignature.getVersion());
        PGPSignatureSubpacketVector hPackets = directKeySignature.getHashedSubPackets();
        isNotNull("Subpackets MUST contain issuer-fingerprint subpacket",
                hPackets.getIssuerFingerprint());
        isFalse("Subpackets MUST NOT contain issuer-key-id subpacket",
                hPackets.hasSubpacket(SignatureSubpacketTags.ISSUER_KEY_ID));
        isNotNull("Subpackets MUST contain signature creation-time subpacket",
                hPackets.getSignatureCreationTime());
        isEquals("Sign-Only primary key MUST carry CS flags",
                KeyFlags.CERTIFY_OTHER | KeyFlags.SIGN_DATA, hPackets.getKeyFlags());

        isEquals("Key version mismatch", 6, primaryKey.getPublicKey().getVersion());
        isEquals("Key MUST be unprotected", SecretKeyPacket.USAGE_NONE, primaryKey.getS2KUsage());
    }

    private void testGenerateAEADProtectedSignOnlyKey(APIProvider apiProvider)
            throws PGPException
    {
        OpenPGPV6KeyGenerator generator = apiProvider.getKeyGenerator(true);
        PGPSecretKeyRing secretKeys = generator.signOnlyKey("passphrase".toCharArray());

        Iterator<PGPSecretKey> it = secretKeys.getSecretKeys();
        PGPSecretKey primaryKey = it.next();
        isFalse("sign-only key MUST consists of only a single key", it.hasNext());

        isEquals("Key MUST be AEAD-protected", SecretKeyPacket.USAGE_AEAD, primaryKey.getS2KUsage());
        isNotNull("Secret key MUST be retrievable using the proper passphrase",
                primaryKey.extractKeyPair(
                        new BcPBESecretKeyDecryptorBuilder(new BcPGPDigestCalculatorProvider())
                                .build("passphrase".toCharArray())));
    }

    private void testGenerateCFBProtectedSignOnlyKey(APIProvider apiProvider)
            throws PGPException
    {
        OpenPGPV6KeyGenerator generator = apiProvider.getKeyGenerator(false);
        PGPSecretKeyRing secretKeys = generator.signOnlyKey("passphrase".toCharArray());

        Iterator<PGPSecretKey> it = secretKeys.getSecretKeys();
        PGPSecretKey primaryKey = it.next();
        isFalse("sign-only key MUST consists of only a single key", it.hasNext());

        isEquals("Key MUST be CFB-protected", SecretKeyPacket.USAGE_SHA1, primaryKey.getS2KUsage());
        isNotNull("Secret key MUST be retrievable using the proper passphrase",
                primaryKey.extractKeyPair(
                        new BcPBESecretKeyDecryptorBuilder(new BcPGPDigestCalculatorProvider())
                                .build("passphrase".toCharArray())));
    }

    private void testGenerateClassicKeyBaseCase(APIProvider apiProvider)
            throws PGPException
    {
        Date creationTime = currentTimeRounded();
        OpenPGPV6KeyGenerator generator = apiProvider.getKeyGenerator(creationTime);
        PGPSecretKeyRing secretKeys = generator
                .classicKey("Alice <alice@example.com>", null);

        Iterator<PGPSecretKey> keys = secretKeys.getSecretKeys();
        PGPSecretKey primaryKey = keys.next();
        isEquals("Primary key version mismatch", PublicKeyPacket.VERSION_6,
                primaryKey.getPublicKey().getVersion());
        isEquals(creationTime, primaryKey.getPublicKey().getCreationTime());
        isTrue("Primary key uses signing-capable algorithm",
                PublicKeyUtils.isSigningAlgorithm(primaryKey.getPublicKey().getAlgorithm()));
        PGPSignature directKeySig = primaryKey.getPublicKey().getKeySignatures().next();
        isEquals("Primary key of a classic key MUST carry C key flag.",
                KeyFlags.CERTIFY_OTHER, directKeySig.getHashedSubPackets().getKeyFlags());

        // Test UIDs
        Iterator<String> uids = primaryKey.getUserIDs();
        isEquals("Alice <alice@example.com>", uids.next());
        isFalse(uids.hasNext());

        // Test signing subkey
        PGPSecretKey signingSubkey = keys.next();
        isEquals("Signing key version mismatch", PublicKeyPacket.VERSION_6,
                signingSubkey.getPublicKey().getVersion());
        isTrue("Signing subkey uses signing-capable algorithm",
                PublicKeyUtils.isSigningAlgorithm(signingSubkey.getPublicKey().getAlgorithm()));
        isEquals(creationTime, signingSubkey.getPublicKey().getCreationTime());
        PGPSignature signingKeyBinding = signingSubkey.getPublicKey().getKeySignatures().next();
        isEquals("Signing subkey MUST carry S key flag.",
                KeyFlags.SIGN_DATA, signingKeyBinding.getHashedSubPackets().getKeyFlags());
        isNotNull("Signing subkey binding MUST carry primary key binding sig",
                signingKeyBinding.getHashedSubPackets().getEmbeddedSignatures().get(0));

        // Test encryption subkey
        PGPSecretKey encryptionSubkey = keys.next();
        isEquals("Encryption key version mismatch", PublicKeyPacket.VERSION_6,
                encryptionSubkey.getPublicKey().getVersion());
        isTrue("Encryption subkey uses encryption-capable algorithm",
                PublicKeyUtils.isEncryptionAlgorithm(encryptionSubkey.getPublicKey().getAlgorithm()));
        isEquals(creationTime, encryptionSubkey.getPublicKey().getCreationTime());
        PGPSignature encryptionKeyBinding = encryptionSubkey.getPublicKey().getKeySignatures().next();
        isEquals("Encryption key MUST carry encryption flags",
                KeyFlags.ENCRYPT_COMMS | KeyFlags.ENCRYPT_STORAGE,
                encryptionKeyBinding.getHashedSubPackets().getKeyFlags());

        // Test has no additional keys
        isFalse(keys.hasNext());

        // Test all keys are unprotected
        for (PGPSecretKey key : secretKeys)
        {
            isEquals("(Sub-)keys MUST be unprotected", SecretKeyPacket.USAGE_NONE, key.getS2KUsage());
        }
    }

    private void testGenerateProtectedTypicalKey(APIProvider apiProvider)
            throws PGPException
    {
        Date creationTime = currentTimeRounded();
        OpenPGPV6KeyGenerator generator = apiProvider.getKeyGenerator(creationTime);
        PGPSecretKeyRing secretKeys = generator
                .classicKey("Alice <alice@example.com>", "passphrase".toCharArray());

        // Test creation time
        for (PGPPublicKey key : secretKeys.toCertificate())
        {
            isEquals(creationTime, key.getCreationTime());
            for (Iterator<PGPSignature> it = key.getSignatures(); it.hasNext(); )
            {
                PGPSignature sig = it.next();
                isEquals(creationTime, sig.getCreationTime());
            }
        }

        PGPPublicKey primaryKey = secretKeys.getPublicKey();
        // Test UIDs
        Iterator<String> uids = primaryKey.getUserIDs();
        isEquals("Alice <alice@example.com>", uids.next());
        isFalse(uids.hasNext());

        for (PGPSecretKey key : secretKeys)
        {
            isEquals("(Sub-)keys MUST be protected", SecretKeyPacket.USAGE_AEAD, key.getS2KUsage());
        }
    }

    private void testGenerateEd25519x25519Key(APIProvider apiProvider)
            throws PGPException
    {
        Date currentTime = currentTimeRounded();
        String userId = "Foo <bar@baz>";
        OpenPGPV6KeyGenerator generator = apiProvider.getKeyGenerator(currentTime);

        PGPSecretKeyRing secretKey = generator.ed25519x25519Key(userId, null);

        Iterator<PGPSecretKey> iterator = secretKey.getSecretKeys();
        PGPSecretKey primaryKey = iterator.next();
        PGPSecretKey signingSubkey = iterator.next();
        PGPSecretKey encryptionSubkey = iterator.next();
        isFalse("Unexpected key", iterator.hasNext());

        isEquals(PublicKeyAlgorithmTags.Ed25519, primaryKey.getPublicKey().getAlgorithm());
        Iterator<PGPSignature> keySignatures = primaryKey.getPublicKey().getKeySignatures();
        PGPSignature directKeySignature = keySignatures.next();
        isFalse(keySignatures.hasNext());
        PGPSignatureSubpacketVector hashedSubpackets = directKeySignature.getHashedSubPackets();
        isEquals(KeyFlags.CERTIFY_OTHER, hashedSubpackets.getKeyFlags());

        Iterator<String> userIds = primaryKey.getUserIDs();
        isEquals(userId, userIds.next());
        isFalse(userIds.hasNext());
        Iterator<PGPSignature> userIdSignatures = primaryKey.getPublicKey().getSignaturesForID(userId);
        PGPSignature userIdSig = userIdSignatures.next();
        isFalse(userIdSignatures.hasNext());
        isEquals(PGPSignature.POSITIVE_CERTIFICATION, userIdSig.getSignatureType());

        isEquals(PublicKeyAlgorithmTags.Ed25519, signingSubkey.getPublicKey().getAlgorithm());
        Iterator<PGPSignature> signingSubkeySigs = signingSubkey.getPublicKey().getKeySignatures();
        PGPSignature signingSubkeySig = signingSubkeySigs.next();
        isFalse(signingSubkeySigs.hasNext());
        isEquals(PGPSignature.SUBKEY_BINDING, signingSubkeySig.getSignatureType());
        hashedSubpackets = signingSubkeySig.getHashedSubPackets();
        isEquals(KeyFlags.SIGN_DATA, hashedSubpackets.getKeyFlags());

        isEquals(PublicKeyAlgorithmTags.X25519, encryptionSubkey.getPublicKey().getAlgorithm());
        Iterator<PGPSignature> encryptionSubkeySigs = encryptionSubkey.getPublicKey().getKeySignatures();
        PGPSignature encryptionSubkeySig = encryptionSubkeySigs.next();
        isFalse(encryptionSubkeySigs.hasNext());
        isEquals(PGPSignature.SUBKEY_BINDING, encryptionSubkeySig.getSignatureType());
        hashedSubpackets = encryptionSubkeySig.getHashedSubPackets();
        isEquals(KeyFlags.ENCRYPT_COMMS | KeyFlags.ENCRYPT_STORAGE, hashedSubpackets.getKeyFlags());
    }

    private void testGenerateEd448x448Key(APIProvider apiProvider)
            throws PGPException
    {
        Date currentTime = currentTimeRounded();
        String userId = "Foo <bar@baz>";
        OpenPGPV6KeyGenerator generator = apiProvider.getKeyGenerator(currentTime);

        PGPSecretKeyRing secretKey = generator.ed448x448Key(userId, null);

        Iterator<PGPSecretKey> iterator = secretKey.getSecretKeys();
        PGPSecretKey primaryKey = iterator.next();
        PGPSecretKey signingSubkey = iterator.next();
        PGPSecretKey encryptionSubkey = iterator.next();
        isFalse("Unexpected key", iterator.hasNext());

        isEquals(PublicKeyAlgorithmTags.Ed448, primaryKey.getPublicKey().getAlgorithm());
        Iterator<PGPSignature> keySignatures = primaryKey.getPublicKey().getKeySignatures();
        PGPSignature directKeySignature = keySignatures.next();
        isFalse(keySignatures.hasNext());
        PGPSignatureSubpacketVector hashedSubpackets = directKeySignature.getHashedSubPackets();
        isEquals(KeyFlags.CERTIFY_OTHER, hashedSubpackets.getKeyFlags());

        Iterator<String> userIds = primaryKey.getUserIDs();
        isEquals(userId, userIds.next());
        isFalse(userIds.hasNext());
        Iterator<PGPSignature> userIdSignatures = primaryKey.getPublicKey().getSignaturesForID(userId);
        PGPSignature userIdSig = userIdSignatures.next();
        isFalse(userIdSignatures.hasNext());
        isEquals(PGPSignature.POSITIVE_CERTIFICATION, userIdSig.getSignatureType());

        isEquals(PublicKeyAlgorithmTags.Ed448, signingSubkey.getPublicKey().getAlgorithm());
        Iterator<PGPSignature> signingSubkeySigs = signingSubkey.getPublicKey().getKeySignatures();
        PGPSignature signingSubkeySig = signingSubkeySigs.next();
        isFalse(signingSubkeySigs.hasNext());
        isEquals(PGPSignature.SUBKEY_BINDING, signingSubkeySig.getSignatureType());
        hashedSubpackets = signingSubkeySig.getHashedSubPackets();
        isEquals(KeyFlags.SIGN_DATA, hashedSubpackets.getKeyFlags());

        isEquals(PublicKeyAlgorithmTags.X448, encryptionSubkey.getPublicKey().getAlgorithm());
        Iterator<PGPSignature> encryptionSubkeySigs = encryptionSubkey.getPublicKey().getKeySignatures();
        PGPSignature encryptionSubkeySig = encryptionSubkeySigs.next();
        isFalse(encryptionSubkeySigs.hasNext());
        isEquals(PGPSignature.SUBKEY_BINDING, encryptionSubkeySig.getSignatureType());
        hashedSubpackets = encryptionSubkeySig.getHashedSubPackets();
        isEquals(KeyFlags.ENCRYPT_COMMS | KeyFlags.ENCRYPT_STORAGE, hashedSubpackets.getKeyFlags());
    }

    private void testGenerateCustomKey(APIProvider apiProvider)
            throws PGPException
    {
        Date creationTime = currentTimeRounded();
        OpenPGPV6KeyGenerator generator = apiProvider.getKeyGenerator(creationTime);

        PGPSecretKeyRing secretKey = generator
                .withPrimaryKey(
                        keyGen -> keyGen.generateRsaKeyPair(4096),
                        subpackets ->
                        {
                            subpackets.removePacketsOfType(SignatureSubpacketTags.KEY_FLAGS);
                            subpackets.setKeyFlags(KeyFlags.CERTIFY_OTHER);

                            subpackets.removePacketsOfType(SignatureSubpacketTags.FEATURES);
                            subpackets.setFeature(false, Features.FEATURE_SEIPD_V2);

                            subpackets.addNotationData(false, true,
                                    "notation@example.com", "CYBER");

                            subpackets.setPreferredKeyServer(false, "https://example.com/openpgp/cert.asc");
                            return subpackets;
                        },
                        "primary-key-passphrase".toCharArray())
                .addUserId("Alice <alice@example.com>", PGPSignature.DEFAULT_CERTIFICATION, null)
                .addSigningSubkey(
                        PGPKeyPairGenerator::generateEd448KeyPair,
                        bindingSubpackets ->
                        {
                            bindingSubpackets.addNotationData(false, true,
                                    "notation@example.com", "ZAUBER");
                            return bindingSubpackets;
                        },
                        null,
                        "signing-key-passphrase".toCharArray())
                .addEncryptionSubkey(PGPKeyPairGenerator::generateX448KeyPair,
                        "encryption-key-passphrase".toCharArray())
                .build();

        Iterator<PGPSecretKey> keyIt = secretKey.getSecretKeys();
        PGPSecretKey primaryKey = keyIt.next();
        isEquals("Primary key MUST be RSA_GENERAL",
                PublicKeyAlgorithmTags.RSA_GENERAL, primaryKey.getPublicKey().getAlgorithm());
        isEquals("Primary key MUST be 4096 bits", 4096, primaryKey.getPublicKey().getBitStrength());
        isEquals("Primary key creation time mismatch",
                creationTime, primaryKey.getPublicKey().getCreationTime());
        PGPSignature directKeySig = primaryKey.getPublicKey().getKeySignatures().next();
        PGPSignatureSubpacketVector hashedSubpackets = directKeySig.getHashedSubPackets();
        isEquals("Primary key key flags mismatch",
                KeyFlags.CERTIFY_OTHER, hashedSubpackets.getKeyFlags());
        isEquals("Primary key features mismatch",
                Features.FEATURE_SEIPD_V2, hashedSubpackets.getFeatures().getFeatures());
        isEquals("Primary key sig notation data mismatch",
                "CYBER",
                hashedSubpackets.getNotationDataOccurrences("notation@example.com")[0].getNotationValue());

        Iterator<String> uids = primaryKey.getUserIDs();
        String uid = uids.next();
        isFalse("Unexpected additional UID", uids.hasNext());
        PGPSignature uidSig = primaryKey.getPublicKey().getSignaturesForID(uid).next();
        isEquals("UID binding sig type mismatch",
                PGPSignature.DEFAULT_CERTIFICATION, uidSig.getSignatureType());

        PGPSecretKey signingSubkey = keyIt.next();
        isEquals("Subkey MUST be Ed448",
                PublicKeyAlgorithmTags.Ed448, signingSubkey.getPublicKey().getAlgorithm());
        isEquals("Subkey creation time mismatch",
                creationTime, signingSubkey.getPublicKey().getCreationTime());
        PGPSignature sigSubBinding = signingSubkey.getPublicKey().getKeySignatures().next();
        PGPSignatureSubpacketVector sigSubBindHashPkts = sigSubBinding.getHashedSubPackets();
        isEquals("Encryption subkey key flags mismatch",
                KeyFlags.SIGN_DATA, sigSubBindHashPkts.getKeyFlags());
        isEquals("Subkey notation data mismatch",
                "ZAUBER",
                sigSubBindHashPkts.getNotationDataOccurrences("notation@example.com")[0].getNotationValue());
        isFalse("Missing embedded primary key binding signature",
                sigSubBindHashPkts.getEmbeddedSignatures().isEmpty());

        PGPSecretKey encryptionSubkey = keyIt.next();
        isFalse("Unexpected additional subkey", keyIt.hasNext());
        isEquals("Subkey MUST be X448",
                PublicKeyAlgorithmTags.X448, encryptionSubkey.getPublicKey().getAlgorithm());
        isEquals("Subkey creation time mismatch",
                creationTime, encryptionSubkey.getPublicKey().getCreationTime());
        PGPSignature encryptionBinding = encryptionSubkey.getPublicKey().getKeySignatures().next();
        PGPSignatureSubpacketVector encBindHashPkts = encryptionBinding.getHashedSubPackets();
        isEquals("Encryption subkey key flags mismatch",
                KeyFlags.ENCRYPT_COMMS | KeyFlags.ENCRYPT_STORAGE, encBindHashPkts.getKeyFlags());
        isTrue("Unexpected embedded primary key binding signature in encryption subkey binding",
                encBindHashPkts.getEmbeddedSignatures().isEmpty());

        BcPBESecretKeyDecryptorBuilder keyDecryptorBuilder = new BcPBESecretKeyDecryptorBuilder(
                new BcPGPDigestCalculatorProvider());

        isNotNull("Could not decrypt primary key using correct passphrase",
                primaryKey.extractPrivateKey(keyDecryptorBuilder.build("primary-key-passphrase".toCharArray())));
        isNotNull("Could not decrypt signing subkey using correct passphrase",
                signingSubkey.extractPrivateKey(keyDecryptorBuilder.build("signing-key-passphrase".toCharArray())));
        isNotNull("Could not decrypt encryption subkey using correct passphrase",
                encryptionSubkey.extractPrivateKey(keyDecryptorBuilder.build("encryption-key-passphrase".toCharArray())));
    }

    private void testEnforcesPrimaryOrSubkeyType(APIProvider apiProvider)
            throws PGPException
    {
        isNotNull(testException(
                "Primary key MUST NOT consist of subkey packet.",
                "IllegalArgumentException",
                () ->
                        apiProvider.getKeyGenerator().withPrimaryKey((KeyPairGeneratorCallback) keyGenCallback ->
                                keyGenCallback.generateSigningSubkey()
                                        .asSubkey(new BcKeyFingerprintCalculator())) // subkey as primary key is illegal
        ));

        isNotNull(testException(
                "Encryption subkey MUST NOT consist of a primary key packet.",
                "IllegalArgumentException",
                () ->
                        apiProvider.getKeyGenerator().withPrimaryKey()
                                .addEncryptionSubkey(new BcPGPKeyPairGeneratorProvider()
                                        .get(6, new Date())
                                        .generateX25519KeyPair(), null, null) // primary key as subkey is illegal
        ));

        isNotNull(testException(
                "Signing subkey MUST NOT consist of primary key packet.",
                "IllegalArgumentException",
                () ->
                        apiProvider.getKeyGenerator().withPrimaryKey()
                                .addSigningSubkey(new BcPGPKeyPairGeneratorProvider()
                                        .get(6, new Date())
                                        .generateEd25519KeyPair(), null, null, null) // primary key as subkey is illegal
        ));
    }

    private abstract static class APIProvider
    {
        public OpenPGPV6KeyGenerator getKeyGenerator()
                throws PGPException
        {
            return getKeyGenerator(new Date());
        }

        public OpenPGPV6KeyGenerator getKeyGenerator(Date creationTime)
                throws PGPException
        {
            return getKeyGenerator(OpenPGPV6KeyGenerator.DEFAULT_SIGNATURE_HASH_ALGORITHM, creationTime, true);
        }

        public OpenPGPV6KeyGenerator getKeyGenerator(boolean aeadProtection)
                throws PGPException
        {
            return getKeyGenerator(OpenPGPV6KeyGenerator.DEFAULT_SIGNATURE_HASH_ALGORITHM, new Date(), aeadProtection);
        }

        public abstract OpenPGPV6KeyGenerator getKeyGenerator(int signatureHashAlgorithm, Date creationTime, boolean aeadProtection)
                throws PGPException;
    }

    public static void main(String[] args)
    {
        runTest(new OpenPGPV6KeyGeneratorTest());
    }
}
