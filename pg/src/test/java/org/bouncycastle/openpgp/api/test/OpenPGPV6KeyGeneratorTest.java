package org.bouncycastle.openpgp.api.test;

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
import org.bouncycastle.openpgp.api.OpenPGPV6KeyGenerator;
import org.bouncycastle.openpgp.api.bc.BcOpenPGPV6KeyGenerator;
import org.bouncycastle.openpgp.api.jcajce.JcaOpenPGPV6KeyGenerator;
import org.bouncycastle.openpgp.operator.PGPKeyPairGenerator;
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;
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
        testGenerateSignOnlyKeyBaseCase(apiProvider);
        testGenerateAEADProtectedSignOnlyKey(apiProvider);
        testGenerateCFBProtectedSignOnlyKey(apiProvider);

        testGenerateClassicKeyBaseCase(apiProvider);
        testGenerateProtectedTypicalKey(apiProvider);

        testGenerateCustomKey(apiProvider);
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
