package org.bouncycastle.openpgp.api.test;

import java.io.IOException;
import java.util.Date;
import java.util.Iterator;

import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyPacket;
import org.bouncycastle.bcpg.PublicKeyUtils;
import org.bouncycastle.bcpg.SecretKeyPacket;
import org.bouncycastle.bcpg.SignaturePacket;
import org.bouncycastle.bcpg.SignatureSubpacketTags;
import org.bouncycastle.bcpg.sig.Features;
import org.bouncycastle.bcpg.sig.KeyFlags;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.bouncycastle.openpgp.PGPSignatureSubpacketVector;
import org.bouncycastle.openpgp.api.KeyPairGeneratorCallback;
import org.bouncycastle.openpgp.api.OpenPGPApi;
import org.bouncycastle.openpgp.api.OpenPGPCertificate;
import org.bouncycastle.openpgp.api.OpenPGPKey;
import org.bouncycastle.openpgp.api.OpenPGPKeyGenerator;
import org.bouncycastle.openpgp.api.SignatureParameters;
import org.bouncycastle.openpgp.api.SignatureSubpacketsFunction;
import org.bouncycastle.openpgp.operator.PGPKeyPairGenerator;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.bc.BcPGPKeyPairGeneratorProvider;

public class OpenPGPV6KeyGeneratorTest
    extends APITest
{
    @Override
    public String getName()
    {
        return "OpenPGPV6KeyGeneratorTest";
    }

    @Override
    protected void performTestWith(OpenPGPApi api)
        throws PGPException, IOException
    {
        testGenerateCustomKey(api);
        testGenerateMinimalKey(api);

        testGenerateSignOnlyKeyBaseCase(api);
        testGenerateAEADProtectedSignOnlyKey(api);
        testGenerateCFBProtectedSignOnlyKey(api);

        testGenerateClassicKeyBaseCase(api);
        testGenerateProtectedTypicalKey(api);

        testGenerateEd25519x25519Key(api);
        testGenerateEd448x448Key(api);

        testEnforcesPrimaryOrSubkeyType(api);
        testGenerateKeyWithoutSignatures(api);
    }

    private void testGenerateSignOnlyKeyBaseCase(OpenPGPApi api)
        throws PGPException
    {
        OpenPGPKeyGenerator generator = api.generateKey();
        OpenPGPKey key = generator.signOnlyKey().build();
        PGPSecretKeyRing secretKeys = key.getPGPKeyRing();

        Iterator<PGPSecretKey> it = secretKeys.getSecretKeys();
        PGPSecretKey primaryKey = (PGPSecretKey)it.next();
        isFalse("sign-only key MUST consists of only a single key", it.hasNext());
        PGPSignature directKeySignature = (PGPSignature)primaryKey.getPublicKey().getKeySignatures().next();
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

    private void testGenerateAEADProtectedSignOnlyKey(OpenPGPApi api)
        throws PGPException
    {
        OpenPGPKeyGenerator generator = api.generateKey(new Date(), true);
        OpenPGPKey key = generator.signOnlyKey().build("passphrase".toCharArray());
        PGPSecretKeyRing secretKeys = key.getPGPKeyRing();

        Iterator<PGPSecretKey> it = secretKeys.getSecretKeys();
        PGPSecretKey primaryKey = (PGPSecretKey)it.next();
        isFalse("sign-only key MUST consists of only a single key", it.hasNext());

        isEquals("Key MUST be AEAD-protected", SecretKeyPacket.USAGE_AEAD, primaryKey.getS2KUsage());
        isNotNull("Secret key MUST be retrievable using the proper passphrase",
            primaryKey.extractKeyPair(
                new BcPBESecretKeyDecryptorBuilder(new BcPGPDigestCalculatorProvider())
                    .build("passphrase".toCharArray())));
    }

    private void testGenerateCFBProtectedSignOnlyKey(OpenPGPApi api)
        throws PGPException
    {
        OpenPGPKeyGenerator generator = api.generateKey(new Date(), false);
        OpenPGPKey key = generator.signOnlyKey().build("passphrase".toCharArray());
        PGPSecretKeyRing secretKeys = key.getPGPKeyRing();

        Iterator<PGPSecretKey> it = secretKeys.getSecretKeys();
        PGPSecretKey primaryKey = (PGPSecretKey)it.next();
        isFalse("sign-only key MUST consists of only a single key", it.hasNext());

        isEquals("Key MUST be CFB-protected", SecretKeyPacket.USAGE_SHA1, primaryKey.getS2KUsage());
        isNotNull("Secret key MUST be retrievable using the proper passphrase",
            primaryKey.extractKeyPair(
                new BcPBESecretKeyDecryptorBuilder(new BcPGPDigestCalculatorProvider())
                    .build("passphrase".toCharArray())));
    }

    private void testGenerateClassicKeyBaseCase(OpenPGPApi api)
        throws PGPException
    {
        Date creationTime = currentTimeRounded();
        OpenPGPKeyGenerator generator = api.generateKey(creationTime);
        OpenPGPKey key = generator
            .classicKey("Alice <alice@example.com>").build();
        PGPSecretKeyRing secretKeys = key.getPGPKeyRing();

        Iterator<PGPSecretKey> keys = secretKeys.getSecretKeys();
        PGPSecretKey primaryKey = (PGPSecretKey)keys.next();
        isEquals("Primary key version mismatch", PublicKeyPacket.VERSION_6,
            primaryKey.getPublicKey().getVersion());
        isEquals(creationTime, primaryKey.getPublicKey().getCreationTime());
        isTrue("Primary key uses signing-capable algorithm",
            PublicKeyUtils.isSigningAlgorithm(primaryKey.getPublicKey().getAlgorithm()));
        PGPSignature directKeySig = (PGPSignature)primaryKey.getPublicKey().getKeySignatures().next();
        isEquals("Primary key of a classic key MUST carry C key flag.",
            KeyFlags.CERTIFY_OTHER, directKeySig.getHashedSubPackets().getKeyFlags());

        // Test UIDs
        Iterator<String> uids = primaryKey.getUserIDs();
        isEquals("Alice <alice@example.com>", uids.next());
        isFalse(uids.hasNext());

        // Test signing subkey
        PGPSecretKey signingSubkey = (PGPSecretKey)keys.next();
        isEquals("Signing key version mismatch", PublicKeyPacket.VERSION_6,
            signingSubkey.getPublicKey().getVersion());
        isTrue("Signing subkey uses signing-capable algorithm",
            PublicKeyUtils.isSigningAlgorithm(signingSubkey.getPublicKey().getAlgorithm()));
        isEquals(creationTime, signingSubkey.getPublicKey().getCreationTime());
        PGPSignature signingKeyBinding = (PGPSignature)signingSubkey.getPublicKey().getKeySignatures().next();
        isEquals("Signing subkey MUST carry S key flag.",
            KeyFlags.SIGN_DATA, signingKeyBinding.getHashedSubPackets().getKeyFlags());
        isNotNull("Signing subkey binding MUST carry primary key binding sig",
            signingKeyBinding.getHashedSubPackets().getEmbeddedSignatures().get(0));

        // Test encryption subkey
        PGPSecretKey encryptionSubkey = (PGPSecretKey)keys.next();
        isEquals("Encryption key version mismatch", PublicKeyPacket.VERSION_6,
            encryptionSubkey.getPublicKey().getVersion());
        isTrue("Encryption subkey uses encryption-capable algorithm",
            encryptionSubkey.getPublicKey().isEncryptionKey());
        isEquals(creationTime, encryptionSubkey.getPublicKey().getCreationTime());
        PGPSignature encryptionKeyBinding = (PGPSignature)encryptionSubkey.getPublicKey().getKeySignatures().next();
        isEquals("Encryption key MUST carry encryption flags",
            KeyFlags.ENCRYPT_COMMS | KeyFlags.ENCRYPT_STORAGE,
            encryptionKeyBinding.getHashedSubPackets().getKeyFlags());

        // Test has no additional keys
        isFalse(keys.hasNext());

        // Test all keys are unprotected
        for (Iterator it = secretKeys.getSecretKeys(); it.hasNext();)
        {
            PGPSecretKey k = (PGPSecretKey)it.next();
            isEquals("(Sub-)keys MUST be unprotected", SecretKeyPacket.USAGE_NONE, k.getS2KUsage());
        }
    }

    private void testGenerateProtectedTypicalKey(OpenPGPApi api)
        throws PGPException
    {
        Date creationTime = currentTimeRounded();
        OpenPGPKeyGenerator generator = api.generateKey(creationTime);
        OpenPGPKey key = generator
            .classicKey("Alice <alice@example.com>").build("passphrase".toCharArray());
        PGPSecretKeyRing secretKeys = key.getPGPKeyRing();

        // Test creation time
        for (Iterator it = secretKeys.toCertificate().iterator(); it.hasNext();)
        {
            PGPPublicKey k = (PGPPublicKey)it.next();
            isEquals(creationTime, k.getCreationTime());
            for (Iterator<PGPSignature> its = k.getSignatures(); its.hasNext(); )
            {
                PGPSignature sig = (PGPSignature)its.next();
                isEquals(creationTime, sig.getCreationTime());
            }
        }

        PGPPublicKey primaryKey = secretKeys.getPublicKey();
        // Test UIDs
        Iterator<String> uids = primaryKey.getUserIDs();
        isEquals("Alice <alice@example.com>", uids.next());
        isFalse(uids.hasNext());

        for (Iterator it = secretKeys.getSecretKeys(); it.hasNext();)
        {
            PGPSecretKey k = (PGPSecretKey)it.next();
            isEquals("(Sub-)keys MUST be protected", SecretKeyPacket.USAGE_AEAD, k.getS2KUsage());

        }
    }

    private void testGenerateEd25519x25519Key(OpenPGPApi api)
            throws PGPException
    {
        Date currentTime = currentTimeRounded();
        String userId = "Foo <bar@baz>";
        OpenPGPKeyGenerator generator = api.generateKey(currentTime);

        OpenPGPKey key = generator.ed25519x25519Key(userId).build();
        PGPSecretKeyRing secretKey = key.getPGPKeyRing();

        Iterator<PGPSecretKey> iterator = secretKey.getSecretKeys();
        PGPSecretKey primaryKey = (PGPSecretKey)iterator.next();
        PGPSecretKey signingSubkey = (PGPSecretKey)iterator.next();
        PGPSecretKey encryptionSubkey = (PGPSecretKey)iterator.next();
        isFalse("Unexpected key", iterator.hasNext());

        isEquals(PublicKeyAlgorithmTags.Ed25519, primaryKey.getPublicKey().getAlgorithm());
        Iterator<PGPSignature> keySignatures = primaryKey.getPublicKey().getKeySignatures();
        PGPSignature directKeySignature = (PGPSignature)keySignatures.next();
        isFalse(keySignatures.hasNext());
        PGPSignatureSubpacketVector hashedSubpackets = directKeySignature.getHashedSubPackets();
        isEquals(KeyFlags.CERTIFY_OTHER, hashedSubpackets.getKeyFlags());

        Iterator<String> userIds = primaryKey.getUserIDs();
        isEquals(userId, userIds.next());
        isFalse(userIds.hasNext());
        Iterator<PGPSignature> userIdSignatures = primaryKey.getPublicKey().getSignaturesForID(userId);
        PGPSignature userIdSig = (PGPSignature)userIdSignatures.next();
        isFalse(userIdSignatures.hasNext());
        isEquals(PGPSignature.POSITIVE_CERTIFICATION, userIdSig.getSignatureType());

        isEquals(PublicKeyAlgorithmTags.Ed25519, signingSubkey.getPublicKey().getAlgorithm());
        Iterator<PGPSignature> signingSubkeySigs = signingSubkey.getPublicKey().getKeySignatures();
        PGPSignature signingSubkeySig = (PGPSignature)signingSubkeySigs.next();
        isFalse(signingSubkeySigs.hasNext());
        isEquals(PGPSignature.SUBKEY_BINDING, signingSubkeySig.getSignatureType());
        hashedSubpackets = signingSubkeySig.getHashedSubPackets();
        isEquals(KeyFlags.SIGN_DATA, hashedSubpackets.getKeyFlags());

        isEquals(PublicKeyAlgorithmTags.X25519, encryptionSubkey.getPublicKey().getAlgorithm());
        Iterator<PGPSignature> encryptionSubkeySigs = encryptionSubkey.getPublicKey().getKeySignatures();
        PGPSignature encryptionSubkeySig = (PGPSignature)encryptionSubkeySigs.next();
        isFalse(encryptionSubkeySigs.hasNext());
        isEquals(PGPSignature.SUBKEY_BINDING, encryptionSubkeySig.getSignatureType());
        hashedSubpackets = encryptionSubkeySig.getHashedSubPackets();
        isEquals(KeyFlags.ENCRYPT_COMMS | KeyFlags.ENCRYPT_STORAGE, hashedSubpackets.getKeyFlags());
    }

    private void testGenerateEd448x448Key(OpenPGPApi api)
            throws PGPException
    {
        Date currentTime = currentTimeRounded();
        String userId = "Foo <bar@baz>";
        OpenPGPKeyGenerator generator = api.generateKey(currentTime);

        OpenPGPKey key = generator.ed448x448Key(userId).build();
        PGPSecretKeyRing secretKey = key.getPGPKeyRing();

        Iterator<PGPSecretKey> iterator = secretKey.getSecretKeys();
        PGPSecretKey primaryKey = (PGPSecretKey)iterator.next();
        PGPSecretKey signingSubkey = (PGPSecretKey)iterator.next();
        PGPSecretKey encryptionSubkey = (PGPSecretKey)iterator.next();
        isFalse("Unexpected key", iterator.hasNext());

        isEquals(PublicKeyAlgorithmTags.Ed448, primaryKey.getPublicKey().getAlgorithm());
        Iterator<PGPSignature> keySignatures = primaryKey.getPublicKey().getKeySignatures();
        PGPSignature directKeySignature = (PGPSignature)keySignatures.next();
        isFalse(keySignatures.hasNext());
        PGPSignatureSubpacketVector hashedSubpackets = directKeySignature.getHashedSubPackets();
        isEquals(KeyFlags.CERTIFY_OTHER, hashedSubpackets.getKeyFlags());

        Iterator<String> userIds = primaryKey.getUserIDs();
        isEquals(userId, userIds.next());
        isFalse(userIds.hasNext());
        Iterator<PGPSignature> userIdSignatures = primaryKey.getPublicKey().getSignaturesForID(userId);
        PGPSignature userIdSig = (PGPSignature)userIdSignatures.next();
        isFalse(userIdSignatures.hasNext());
        isEquals(PGPSignature.POSITIVE_CERTIFICATION, userIdSig.getSignatureType());

        isEquals(PublicKeyAlgorithmTags.Ed448, signingSubkey.getPublicKey().getAlgorithm());
        Iterator<PGPSignature> signingSubkeySigs = signingSubkey.getPublicKey().getKeySignatures();
        PGPSignature signingSubkeySig = (PGPSignature)signingSubkeySigs.next();
        isFalse(signingSubkeySigs.hasNext());
        isEquals(PGPSignature.SUBKEY_BINDING, signingSubkeySig.getSignatureType());
        hashedSubpackets = signingSubkeySig.getHashedSubPackets();
        isEquals(KeyFlags.SIGN_DATA, hashedSubpackets.getKeyFlags());

        isEquals(PublicKeyAlgorithmTags.X448, encryptionSubkey.getPublicKey().getAlgorithm());
        Iterator<PGPSignature> encryptionSubkeySigs = encryptionSubkey.getPublicKey().getKeySignatures();
        PGPSignature encryptionSubkeySig = (PGPSignature)encryptionSubkeySigs.next();
        isFalse(encryptionSubkeySigs.hasNext());
        isEquals(PGPSignature.SUBKEY_BINDING, encryptionSubkeySig.getSignatureType());
        hashedSubpackets = encryptionSubkeySig.getHashedSubPackets();
        isEquals(KeyFlags.ENCRYPT_COMMS | KeyFlags.ENCRYPT_STORAGE, hashedSubpackets.getKeyFlags());
    }

    private void testGenerateCustomKey(OpenPGPApi api)
        throws PGPException
    {
        Date creationTime = currentTimeRounded();
        OpenPGPKeyGenerator generator = api.generateKey(creationTime, false);

        OpenPGPKey key = generator
            .withPrimaryKey(
                    new KeyPairGeneratorCallback()
                    {
                        public PGPKeyPair generateFrom(PGPKeyPairGenerator generator)
                                throws PGPException
                        {
                            return generator.generateRsaKeyPair(4096);
                        }
                    },
                    SignatureParameters.Callback.Util.modifyHashedSubpackets(new SignatureSubpacketsFunction()
                    {
                        @Override
                        public PGPSignatureSubpacketGenerator apply(PGPSignatureSubpacketGenerator subpackets)
                        {
                            subpackets.removePacketsOfType(SignatureSubpacketTags.KEY_FLAGS);
                            subpackets.setKeyFlags(KeyFlags.CERTIFY_OTHER);

                            subpackets.removePacketsOfType(SignatureSubpacketTags.FEATURES);
                            subpackets.setFeature(false, Features.FEATURE_SEIPD_V2);

                            subpackets.addNotationData(false, true,
                                    "notation@example.com", "CYBER");

                            subpackets.setPreferredKeyServer(false, "https://example.com/openpgp/cert.asc");
                            return subpackets;
                        }
                    }))
            .addUserId("Alice <alice@example.com>")
            .addSigningSubkey(
                    new KeyPairGeneratorCallback()
                    {
                        public PGPKeyPair generateFrom(PGPKeyPairGenerator generator)
                                throws PGPException
                        {
                            return generator.generateEd448KeyPair();
                        }
                    },
                    SignatureParameters.Callback.Util.modifyHashedSubpackets(new SignatureSubpacketsFunction()
                    {
                        @Override
                        public PGPSignatureSubpacketGenerator apply(PGPSignatureSubpacketGenerator subpackets)
                        {
                            subpackets.addNotationData(false, true,
                                    "notation@example.com", "ZAUBER");
                            return subpackets;
                        }
                    }),
                    null)
            .addEncryptionSubkey(
                new KeyPairGeneratorCallback()
                {
                    public PGPKeyPair generateFrom(PGPKeyPairGenerator generator)
                        throws PGPException
                    {
                        return generator.generateX448KeyPair();
                    }
                })
            .build("primary-key-passphrase".toCharArray());
        OpenPGPCertificate.OpenPGPComponentKey encryptionKey = key.getEncryptionKeys().get(0);
        OpenPGPCertificate.OpenPGPComponentKey signingKey = key.getSigningKeys().get(0);
        key = api.editKey(key, "primary-key-passphrase".toCharArray())
                .changePassphrase(encryptionKey.getKeyIdentifier(),
                        "primary-key-passphrase".toCharArray(),
                        "encryption-key-passphrase".toCharArray(),
                        false)
                .changePassphrase(signingKey.getKeyIdentifier(),
                        "primary-key-passphrase".toCharArray(),
                        "signing-key-passphrase".toCharArray(),
                        false)
                .done();

        PGPSecretKeyRing secretKey = key.getPGPKeyRing();
        Iterator<PGPSecretKey> keyIt = secretKey.getSecretKeys();
        PGPSecretKey primaryKey = (PGPSecretKey)keyIt.next();
        isEquals("Primary key MUST be RSA_GENERAL",
            PublicKeyAlgorithmTags.RSA_GENERAL, primaryKey.getPublicKey().getAlgorithm());
        isEquals("Primary key MUST be 4096 bits", 4096, primaryKey.getPublicKey().getBitStrength());
        isEquals("Primary key creation time mismatch",
            creationTime, primaryKey.getPublicKey().getCreationTime());
        PGPSignature directKeySig = (PGPSignature)primaryKey.getPublicKey().getKeySignatures().next();
        PGPSignatureSubpacketVector hashedSubpackets = directKeySig.getHashedSubPackets();
        isEquals("Primary key key flags mismatch",
            KeyFlags.CERTIFY_OTHER, hashedSubpackets.getKeyFlags());
        isEquals("Primary key features mismatch",
            Features.FEATURE_SEIPD_V2, hashedSubpackets.getFeatures().getFeatures());
        isEquals("Primary key sig notation data mismatch",
            "CYBER",
            hashedSubpackets.getNotationDataOccurrences("notation@example.com")[0].getNotationValue());

        Iterator<String> uids = primaryKey.getUserIDs();
        String uid = (String)uids.next();
        isFalse("Unexpected additional UID", uids.hasNext());
        PGPSignature uidSig = (PGPSignature)primaryKey.getPublicKey().getSignaturesForID(uid).next();
        isEquals("UID binding sig type mismatch",
            PGPSignature.POSITIVE_CERTIFICATION, uidSig.getSignatureType());

        PGPSecretKey signingSubkey = (PGPSecretKey)keyIt.next();
        isEquals("Subkey MUST be Ed448",
            PublicKeyAlgorithmTags.Ed448, signingSubkey.getPublicKey().getAlgorithm());
        isEquals("Subkey creation time mismatch",
            creationTime, signingSubkey.getPublicKey().getCreationTime());
        PGPSignature sigSubBinding = (PGPSignature)signingSubkey.getPublicKey().getKeySignatures().next();
        PGPSignatureSubpacketVector sigSubBindHashPkts = sigSubBinding.getHashedSubPackets();
        isEquals("Encryption subkey key flags mismatch",
            KeyFlags.SIGN_DATA, sigSubBindHashPkts.getKeyFlags());
        isEquals("Subkey notation data mismatch",
            "ZAUBER",
            sigSubBindHashPkts.getNotationDataOccurrences("notation@example.com")[0].getNotationValue());
        isFalse("Missing embedded primary key binding signature",
            sigSubBindHashPkts.getEmbeddedSignatures().isEmpty());

        PGPSecretKey encryptionSubkey = (PGPSecretKey)keyIt.next();
        isFalse("Unexpected additional subkey", keyIt.hasNext());
        isEquals("Subkey MUST be X448",
            PublicKeyAlgorithmTags.X448, encryptionSubkey.getPublicKey().getAlgorithm());
        isEquals("Subkey creation time mismatch",
            creationTime, encryptionSubkey.getPublicKey().getCreationTime());
        PGPSignature encryptionBinding = (PGPSignature)encryptionSubkey.getPublicKey().getKeySignatures().next();
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

    private void testGenerateMinimalKey(OpenPGPApi api)
            throws PGPException
    {
        Date creationTime = currentTimeRounded();
        OpenPGPKeyGenerator gen = api.generateKey(creationTime, false);
        OpenPGPKey key = gen.withPrimaryKey(
                new KeyPairGeneratorCallback()
                {
                    @Override
                    public PGPKeyPair generateFrom(PGPKeyPairGenerator generator)
                        throws PGPException
                    {
                        return generator.generateEd25519KeyPair();
                    }
                },
                SignatureParameters.Callback.Util.modifyHashedSubpackets(new SignatureSubpacketsFunction()
                {
                    @Override
                    public PGPSignatureSubpacketGenerator apply(PGPSignatureSubpacketGenerator subpackets)
                    {
                        subpackets.addNotationData(false, true, "foo@bouncycastle.org", "bar");
                        return subpackets;
                    }
                }))
                .addUserId("Alice <alice@example.org>")
                .addEncryptionSubkey()
                .addSigningSubkey()
                .build();
        PGPSecretKeyRing secretKeys = key.getPGPKeyRing();

        // Test creation time
        for(Iterator it = secretKeys.toCertificate().iterator(); it.hasNext(); )
        {
            PGPPublicKey k = (PGPPublicKey)it.next();
            isEquals(creationTime, k.getCreationTime());
            for (Iterator<PGPSignature> itSign = k.getSignatures(); itSign.hasNext(); ) {
                PGPSignature sig = itSign.next();
                isEquals(creationTime, sig.getCreationTime());
            }
        }

        PGPPublicKey primaryKey = secretKeys.getPublicKey();
        // Test UIDs
        Iterator<String> uids = primaryKey.getUserIDs();
        isEquals("Alice <alice@example.org>", uids.next());
        isFalse(uids.hasNext());
    }

    private void testEnforcesPrimaryOrSubkeyType(final OpenPGPApi api)
        throws PGPException
    {
        isNotNull(testException(
            "Primary key MUST NOT consist of subkey packet.",
            "IllegalArgumentException",
            new TestExceptionOperation()
            {
                @Override
                public void operation()
                    throws Exception
                {
                    api.generateKey().withPrimaryKey(
                        new KeyPairGeneratorCallback()
                        {
                            public PGPKeyPair generateFrom(PGPKeyPairGenerator keyGenCallback)
                                throws PGPException
                            {
                                return keyGenCallback.generateSigningSubkey()
                                    .asSubkey(new BcKeyFingerprintCalculator());// subkey as primary key is illegal
                            }
                        });
                }
            }
        ));

        isNotNull(testException(
            "Encryption subkey MUST NOT consist of a primary key packet.",
            "IllegalArgumentException",
            new TestExceptionOperation()
            {
                @Override
                public void operation()
                    throws Exception
                {
                    api.generateKey().withPrimaryKey()
                        .addEncryptionSubkey(
                                new BcPGPKeyPairGeneratorProvider()
                                        .get(6, new Date())
                                        .generateX25519KeyPair(),
                                null); // primary key as subkey is illegal
                }
            }
        ));

        isNotNull(testException(
            "Signing subkey MUST NOT consist of primary key packet.",
            "IllegalArgumentException",
            new TestExceptionOperation()
            {
                @Override
                public void operation()
                    throws Exception
                {
                    api.generateKey().withPrimaryKey()
                        .addSigningSubkey(
                                new BcPGPKeyPairGeneratorProvider()
                                        .get(6, new Date())
                                        .generateEd25519KeyPair(),
                                null,
                                null); // primary key as subkey is illegal
                }
            }
        ));
    }

    private void testGenerateKeyWithoutSignatures(OpenPGPApi api)
            throws PGPException
    {
        OpenPGPKey key = api.generateKey()
                .withPrimaryKey(
                        KeyPairGeneratorCallback.Util.primaryKey(),
                        // No direct-key sig
                        new SignatureParameters.Callback()
                        {
                            @Override
                            public SignatureParameters apply(SignatureParameters parameters) {
                                return null;
                            }
                        })
                .addSigningSubkey(
                        KeyPairGeneratorCallback.Util.signingKey(),
                        // No subkey binding sig
                        new SignatureParameters.Callback()
                        {
                            @Override
                            public SignatureParameters apply(SignatureParameters parameters)
                            {
                                return null;
                            }
                        },
                        // No primary key binding sig
                        new SignatureParameters.Callback()
                        {
                            @Override
                            public SignatureParameters apply(SignatureParameters parameters)
                            {
                                return null;
                            }
                        })
                .addEncryptionSubkey(
                        KeyPairGeneratorCallback.Util.encryptionKey(),
                        // No subkey binding sig
                        new SignatureParameters.Callback()
                        {
                            @Override
                            public SignatureParameters apply(SignatureParameters parameters)
                            {
                                return null;
                            }
                        })
                .build();

        PGPPublicKeyRing publicKeys = key.getPGPPublicKeyRing();
        Iterator<PGPPublicKey> it = publicKeys.getPublicKeys();

        PGPPublicKey primaryKey = it.next();
        isFalse(primaryKey.getSignatures().hasNext());

        PGPPublicKey signingSubkey = it.next();
        isFalse(signingSubkey.getSignatures().hasNext());

        PGPPublicKey encryptionSubkey = it.next();
        isFalse(encryptionSubkey.getSignatures().hasNext());
    }

    public static void main(String[] args)
    {
        runTest(new OpenPGPV6KeyGeneratorTest());
    }
}
