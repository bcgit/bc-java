package org.bouncycastle.openpgp.api.test;

import org.bouncycastle.bcpg.PublicKeyPacket;
import org.bouncycastle.bcpg.PublicKeyUtils;
import org.bouncycastle.bcpg.SecretKeyPacket;
import org.bouncycastle.bcpg.sig.KeyFlags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.api.OpenPGPV6KeyGenerator;
import org.bouncycastle.openpgp.api.bc.BcOpenPGPV6KeyGenerator;
import org.bouncycastle.openpgp.api.jcajce.JcaOpenPGPV6KeyGenerator;
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
        // Run tests using BC implementation
        performTests(new ImplementationProvider()
        {
            @Override
            public OpenPGPV6KeyGenerator get(int signatureHashAlgorithm, Date creationTime, boolean aeadProtection)
            {
                return new BcOpenPGPV6KeyGenerator(signatureHashAlgorithm, creationTime, aeadProtection);
            }
        });

        // Run tests using Jca implementation
        performTests(new ImplementationProvider()
        {
            @Override
            public OpenPGPV6KeyGenerator get(int signatureHashAlgorithm, Date creationTime, boolean aeadProtection)
                    throws PGPException
            {
                return new JcaOpenPGPV6KeyGenerator(signatureHashAlgorithm, creationTime, new BouncyCastleProvider(), aeadProtection);
            }
        });
    }

    private void performTests(ImplementationProvider implementationProvider)
            throws PGPException, IOException
    {
        testGenerateSignOnlyKeyBaseCase(implementationProvider);
        testGenerateAEADProtectedSignOnlyKey(implementationProvider);
        testGenerateCFBProtectedSignOnlyKey(implementationProvider);

        testGenerateClassicKeyBaseCase(implementationProvider);
        testGenerateProtectedTypicalKey(implementationProvider);
    }

    private void testGenerateSignOnlyKeyBaseCase(ImplementationProvider implementationProvider)
            throws PGPException
    {
        OpenPGPV6KeyGenerator generator = implementationProvider.get();
        PGPSecretKeyRing secretKeys = generator.signOnlyKey();

        Iterator<PGPSecretKey> it = secretKeys.getSecretKeys();
        PGPSecretKey primaryKey = it.next();
        isFalse("sign-only key MUST consists of only a single key", it.hasNext());
        PGPSignature directKeySignature = primaryKey.getPublicKey().getKeySignatures().next();
        isNotNull("Key MUST have direct-key signature", directKeySignature);
        isEquals("Sign-Only primary key MUST carry CS flags",
                KeyFlags.CERTIFY_OTHER | KeyFlags.SIGN_DATA, directKeySignature.getHashedSubPackets().getKeyFlags());

        isEquals("Key version mismatch", 6, primaryKey.getPublicKey().getVersion());
        isEquals("Key MUST be unprotected", SecretKeyPacket.USAGE_NONE, primaryKey.getS2KUsage());
    }

    private void testGenerateAEADProtectedSignOnlyKey(ImplementationProvider implementationProvider)
            throws PGPException
    {
        OpenPGPV6KeyGenerator generator = implementationProvider.get(true);
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

    private void testGenerateCFBProtectedSignOnlyKey(ImplementationProvider implementationProvider)
            throws PGPException
    {
        OpenPGPV6KeyGenerator generator = implementationProvider.get(false);
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

    private void testGenerateClassicKeyBaseCase(ImplementationProvider provider)
            throws PGPException
    {
        Date creationTime = currentTimeRounded();
        OpenPGPV6KeyGenerator generator = provider.get(creationTime);
        PGPSecretKeyRing secretKeys = generator
                .classicKey("Alice <alice@example.com>", null);

        Iterator<PGPSecretKey> keys = secretKeys.getSecretKeys();
        PGPSecretKey primaryKey = keys.next();
        isEquals("Primary key version mismatch", PublicKeyPacket.VERSION_6,
                primaryKey.getPublicKey().getVersion());
        isEquals(creationTime, primaryKey.getPublicKey().getCreationTime());
        isTrue("Primary key uses signing-capable algorithm",
                PublicKeyUtils.isSigningAlgorithm(primaryKey.getPublicKey().getAlgorithm()));
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

        // Test encryption subkey
        PGPSecretKey encryptionSubkey = keys.next();
        isEquals("Encryption key version mismatch", PublicKeyPacket.VERSION_6,
                encryptionSubkey.getPublicKey().getVersion());
        isTrue("Encryption subkey uses encryption-capable algorithm",
                PublicKeyUtils.isEncryptionAlgorithm(encryptionSubkey.getPublicKey().getAlgorithm()));
        isEquals(creationTime, encryptionSubkey.getPublicKey().getCreationTime());

        // Test has no additional keys
        isFalse(keys.hasNext());

        // Test all keys are unprotected
        for (PGPSecretKey key : secretKeys)
        {
            isEquals("(Sub-)keys MUST be unprotected", SecretKeyPacket.USAGE_NONE, key.getS2KUsage());
        }
    }

    private void testGenerateProtectedTypicalKey(ImplementationProvider provider)
            throws PGPException
    {
        Date creationTime = currentTimeRounded();
        OpenPGPV6KeyGenerator generator = provider.get(creationTime);
        PGPSecretKeyRing secretKeys = generator
                .classicKey("Alice <alice@example.com>", "passphrase".toCharArray());

        // Test creation time
        for (PGPPublicKey key : secretKeys.toCertificate())
        {
            isEquals(creationTime, key.getCreationTime());
            for (Iterator<PGPSignature> it = key.getSignatures(); it.hasNext(); ) {
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

    private abstract static class ImplementationProvider
    {
        public OpenPGPV6KeyGenerator get()
                throws PGPException
        {
            return get(new Date());
        }

        public OpenPGPV6KeyGenerator get(Date creationTime)
                throws PGPException
        {
            return get(OpenPGPV6KeyGenerator.DEFAULT_SIGNATURE_HASH_ALGORITHM, creationTime, true);
        }

        public OpenPGPV6KeyGenerator get(boolean aeadProtection)
                throws PGPException
        {
            return get(OpenPGPV6KeyGenerator.DEFAULT_SIGNATURE_HASH_ALGORITHM, new Date(), aeadProtection);
        }

        public abstract OpenPGPV6KeyGenerator get(int signatureHashAlgorithm, Date creationTime, boolean aeadProtection)
                throws PGPException;
    }

    public static void main(String[] args)
    {
        runTest(new OpenPGPV6KeyGeneratorTest());
    }
}
