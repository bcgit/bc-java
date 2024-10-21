package org.bouncycastle.openpgp.api;

import org.bouncycastle.bcpg.AEADAlgorithmTags;
import org.bouncycastle.bcpg.CompressionAlgorithmTags;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyPacket;
import org.bouncycastle.bcpg.PublicKeyUtils;
import org.bouncycastle.bcpg.S2K;
import org.bouncycastle.bcpg.SignatureSubpacketTags;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.bcpg.sig.Features;
import org.bouncycastle.bcpg.sig.KeyFlags;
import org.bouncycastle.bcpg.sig.PreferredAEADCiphersuites;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.bouncycastle.openpgp.operator.KeyFingerPrintCalculator;
import org.bouncycastle.openpgp.operator.PBESecretKeyEncryptor;
import org.bouncycastle.openpgp.operator.PBESecretKeyEncryptorFactory;
import org.bouncycastle.openpgp.operator.PGPContentSignerBuilderProvider;
import org.bouncycastle.openpgp.operator.PGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.PGPKeyPairGenerator;
import org.bouncycastle.openpgp.operator.PGPKeyPairGeneratorProvider;
import org.bouncycastle.util.Arrays;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

/**
 * High-level generator class for OpenPGP v6 keys.
 */
public class OpenPGPV6KeyGenerator
{
    /**
     * Hash algorithm for key signatures if no other one is provided during construction.
     */
    public static final int DEFAULT_SIGNATURE_HASH_ALGORITHM = HashAlgorithmTags.SHA3_512;

    // SECONDS
    private static final long SECONDS_PER_MINUTE = 60;
    private static final long SECONDS_PER_HOUR = 60 * SECONDS_PER_MINUTE;
    private static final long SECONDS_PER_DAY = 24 * SECONDS_PER_HOUR;
    private static final long SECONDS_PER_YEAR = 365 * SECONDS_PER_DAY;

    /**
     * Standard AEAD encryption preferences (SEIPDv2).
     * By default, only announce support for OCB + AES.
     */
    public static SignatureSubpacketsFunction DEFAULT_AEAD_ALGORITHM_PREFERENCES = subpackets ->
    {
        subpackets.removePacketsOfType(SignatureSubpacketTags.PREFERRED_AEAD_ALGORITHMS);
        subpackets.setPreferredAEADCiphersuites(PreferredAEADCiphersuites.builder(false)
                .addCombination(SymmetricKeyAlgorithmTags.AES_256, AEADAlgorithmTags.OCB)
                .addCombination(SymmetricKeyAlgorithmTags.AES_192, AEADAlgorithmTags.OCB)
                .addCombination(SymmetricKeyAlgorithmTags.AES_128, AEADAlgorithmTags.OCB));
        return subpackets;
    };

    /**
     * Standard symmetric-key encryption preferences (SEIPDv1).
     * By default, announce support for AES.
     */
    public static SignatureSubpacketsFunction DEFAULT_SYMMETRIC_KEY_PREFERENCES = subpackets ->
    {
        subpackets.removePacketsOfType(SignatureSubpacketTags.PREFERRED_SYM_ALGS);
        subpackets.setPreferredSymmetricAlgorithms(false, new int[] {
                SymmetricKeyAlgorithmTags.AES_256, SymmetricKeyAlgorithmTags.AES_192, SymmetricKeyAlgorithmTags.AES_128
        });
        return subpackets;
    };

    /**
     * Standard signature hash algorithm preferences.
     * By default, only announce SHA3 and SHA2 algorithms.
     */
    public static SignatureSubpacketsFunction DEFAULT_HASH_ALGORITHM_PREFERENCES = subpackets ->
    {
        subpackets.removePacketsOfType(SignatureSubpacketTags.PREFERRED_HASH_ALGS);
        subpackets.setPreferredHashAlgorithms(false, new int[] {
                HashAlgorithmTags.SHA3_512, HashAlgorithmTags.SHA3_256,
                HashAlgorithmTags.SHA512, HashAlgorithmTags.SHA384, HashAlgorithmTags.SHA256
        });
        return subpackets;
    };

    /**
     * Standard compression algorithm preferences.
     * By default, announce support for all known algorithms.
     */
    public static SignatureSubpacketsFunction DEFAULT_COMPRESSION_ALGORITHM_PREFERENCES = subpackets ->
    {
        subpackets.removePacketsOfType(SignatureSubpacketTags.PREFERRED_COMP_ALGS);
        subpackets.setPreferredCompressionAlgorithms(false, new int[] {
                CompressionAlgorithmTags.UNCOMPRESSED, CompressionAlgorithmTags.ZIP,
                CompressionAlgorithmTags.ZLIB, CompressionAlgorithmTags.BZIP2
        });
        return subpackets;
    };

    /**
     * Standard features to announce.
     * By default, announce SEIPDv1 (modification detection) and SEIPDv2.
     */
    public static SignatureSubpacketsFunction DEFAULT_FEATURES = subpackets ->
    {
        subpackets.removePacketsOfType(SignatureSubpacketTags.FEATURES);
        subpackets.setFeature(false, (byte) (Features.FEATURE_MODIFICATION_DETECTION | Features.FEATURE_SEIPD_V2));
        return subpackets;
    };

    /**
     * Standard signature subpackets for signing subkey's binding signatures.
     * Sets the keyflag subpacket to SIGN_DATA.
     */
    public static SignatureSubpacketsFunction SIGNING_SUBKEY_SUBPACKETS = subpackets ->
    {
        subpackets.removePacketsOfType(SignatureSubpacketTags.KEY_FLAGS);
        subpackets.setKeyFlags(true, KeyFlags.SIGN_DATA);
        return subpackets;
    };

    /**
     * Standard signature subpackets for encryption subkey's binding signatures.
     * Sets the keyflag subpacket to ENCRYPT_STORAGE|ENCRYPT_COMMS.
     */
    public static SignatureSubpacketsFunction ENCRYPTION_SUBKEY_SUBPACKETS = subpackets ->
    {
        subpackets.removePacketsOfType(SignatureSubpacketTags.KEY_FLAGS);
        subpackets.setKeyFlags(true, KeyFlags.ENCRYPT_STORAGE | KeyFlags.ENCRYPT_COMMS);
        return subpackets;
    };

    /**
     * Standard signature subpackets for the direct-key signature.
     * Sets default features, hash-, compression-, symmetric-key-, and AEAD algorithm preferences.
     */
    public static SignatureSubpacketsFunction DIRECT_KEY_SIGNATURE_SUBPACKETS = subpackets ->
    {
        subpackets = DEFAULT_FEATURES.apply(subpackets);
        subpackets = DEFAULT_HASH_ALGORITHM_PREFERENCES.apply(subpackets);
        subpackets = DEFAULT_COMPRESSION_ALGORITHM_PREFERENCES.apply(subpackets);
        subpackets = DEFAULT_SYMMETRIC_KEY_PREFERENCES.apply(subpackets);
        subpackets = DEFAULT_AEAD_ALGORITHM_PREFERENCES.apply(subpackets);
        return subpackets;
    };

    private final Implementation impl; // contains BC or JCA/JCE implementations
    private final Configuration conf;

    /**
     * Generate a new OpenPGP key generator for v6 keys.
     *
     * @param kpGenProvider key pair generator provider
     * @param contentSignerBuilderProvider content signer builder provider
     * @param digestCalculatorProvider digest calculator provider
     * @param keyEncryptionBuilderProvider secret key encryption builder provider (AEAD)
     * @param keyFingerPrintCalculator calculator for key fingerprints
     * @param creationTime key creation time
     */
    public OpenPGPV6KeyGenerator(
            PGPKeyPairGeneratorProvider kpGenProvider,
            PGPContentSignerBuilderProvider contentSignerBuilderProvider,
            PGPDigestCalculatorProvider digestCalculatorProvider,
            PBESecretKeyEncryptorFactory keyEncryptionBuilderProvider,
            KeyFingerPrintCalculator keyFingerPrintCalculator,
            Date creationTime)
    {
        this.impl = new Implementation(kpGenProvider, contentSignerBuilderProvider, digestCalculatorProvider, keyEncryptionBuilderProvider, keyFingerPrintCalculator);
        this.conf = new Configuration(new Date((creationTime.getTime() / 1000) * 1000));
    }

    /**
     * Generate an OpenPGP key consisting of a certify-only primary key,
     * a dedicated signing-subkey and dedicated encryption-subkey.
     * The key will carry the provided user-id and be protected using the provided passphrase.
     * See {@link PGPKeyPairGenerator#generatePrimaryKey()} for the primary key type,
     * {@link PGPKeyPairGenerator#generateSigningSubkey()} for the signing-subkey type and
     * {@link PGPKeyPairGenerator#generateEncryptionSubkey()} for the encryption-subkey key type.
     *
     * @param userId user id
     * @param passphrase nullable passphrase.
     * @return OpenPGP key
     * @throws PGPException if the key cannot be generated
     */
    public PGPSecretKeyRing classicKey(String userId, char[] passphrase)
            throws PGPException
    {
        return withPrimaryKey()
                .addUserId(userId)
                .addSigningSubkey()
                .addEncryptionSubkey()
                .build(passphrase);
    }

    /**
     * Generate an OpenPGP key consisting of an Ed25519 certify-only primary key,
     * a dedicated Ed25519 sign-only subkey and dedicated X25519 encryption-only subkey.
     * The key will carry the provided user-id and be protected using the provided passphrase.
     *
     * @param userId user id
     * @param passphrase nullable passphrase
     * @return OpenPGP key
     * @throws PGPException if the key cannot be generated
     */
    public PGPSecretKeyRing ed25519x25519Key(String userId, char[] passphrase)
            throws PGPException
    {
        return withPrimaryKey(PGPKeyPairGenerator::generateEd25519KeyPair)
                .addSigningSubkey(PGPKeyPairGenerator::generateEd25519KeyPair)
                .addEncryptionSubkey(PGPKeyPairGenerator::generateX25519KeyPair)
                .addUserId(userId)
                .build(passphrase);
    }


    /**
     * Generate an OpenPGP key consisting of an Ed448 certify-only primary key,
     * a dedicated Ed448 sign-only subkey and dedicated X448 encryption-only subkey.
     * The key will carry the provided user-id and be protected using the provided passphrase.
     *
     * @param userId user id
     * @param passphrase nullable passphrase
     * @return OpenPGP key
     * @throws PGPException if the key cannot be generated
     */
    public PGPSecretKeyRing ed448x448Key(String userId, char[] passphrase)
            throws PGPException
    {
        return withPrimaryKey(PGPKeyPairGenerator::generateEd448KeyPair)
                .addSigningSubkey(PGPKeyPairGenerator::generateEd448KeyPair)
                .addEncryptionSubkey(PGPKeyPairGenerator::generateX448KeyPair)
                .addUserId(userId)
                .build(passphrase);
    }

    /**
     * Generate a sign-only OpenPGP key.
     * The key consists of a single, user-id-less primary key, which is capable of signing and certifying.
     * See {@link PGPKeyPairGenerator#generatePrimaryKey()} for the key type.
     *
     * @param passphrase nullable passphrase to protect the key with
     * @return sign-only (+certify) OpenPGP key
     * @throws PGPException if the key cannot be generated
     */
    public PGPSecretKeyRing signOnlyKey(char[] passphrase)
            throws PGPException
    {
        return signOnlyKey(passphrase, null);
    }

    /**
     * Generate a sign-only OpenPGP key.
     * The key consists of a single, user-id-less primary key, which is capable of signing and certifying.
     * It carries a single direct-key signature with signing-related preferences whose subpackets can be
     * modified by providing a {@link SignatureSubpacketsFunction}.
     *
     * @param passphrase nullable passphrase to protect the key with
     * @param userSubpackets callback to modify the direct-key signature subpackets with
     * @return sign-only (+certify) OpenPGP key
     * @throws PGPException if the key cannot be generated
     */
    public PGPSecretKeyRing signOnlyKey(
            char[] passphrase,
            SignatureSubpacketsFunction userSubpackets)
            throws PGPException
    {
        PGPKeyPair primaryKeyPair = impl.kpGenProvider.get(PublicKeyPacket.VERSION_6, conf.keyCreationTime)
                .generatePrimaryKey();
        PBESecretKeyEncryptor encryptor = impl.keyEncryptorBuilderProvider
                .build(passphrase, primaryKeyPair.getPublicKey().getPublicKeyPacket());
        return signOnlyKey(primaryKeyPair, encryptor, userSubpackets);
    }

    /**
     * Generate a sign-only OpenPGP key.
     * The key consists of a single, user-id-less primary key, which is capable of signing and certifying.
     * It carries a single direct-key signature with signing-related preferences whose subpackets can be
     * modified by providing a {@link SignatureSubpacketsFunction}.
     *
     * @param primaryKeyPair signing-capable primary key
     * @param keyEncryptor nullable encryptor to protect the primary key with
     * @param userSubpackets callback to modify the direct-key signature subpackets with
     * @return sign-only (+certify) OpenPGP key
     * @throws PGPException if the key cannot be generated
     */
    public PGPSecretKeyRing signOnlyKey(
            PGPKeyPair primaryKeyPair,
            PBESecretKeyEncryptor keyEncryptor,
            SignatureSubpacketsFunction userSubpackets)
            throws PGPException
    {
        if (!primaryKeyPair.getPublicKey().isMasterKey())
        {
            throw new IllegalArgumentException("Primary key MUST NOT consist of subkey packet.");
        }

        return primaryKeyWithDirectKeySig(primaryKeyPair,
                baseSubpackets ->
                {
                    // remove unrelated subpackets not needed for sign-only keys
                    baseSubpackets.removePacketsOfType(SignatureSubpacketTags.PREFERRED_AEAD_ALGORITHMS);
                    baseSubpackets.removePacketsOfType(SignatureSubpacketTags.PREFERRED_SYM_ALGS);
                    baseSubpackets.removePacketsOfType(SignatureSubpacketTags.PREFERRED_COMP_ALGS);

                    // replace key flags -> CERTIFY_OTHER|SIGN_DATA
                    baseSubpackets.removePacketsOfType(SignatureSubpacketTags.KEY_FLAGS);
                    baseSubpackets.setKeyFlags(true, KeyFlags.CERTIFY_OTHER | KeyFlags.SIGN_DATA);
                    return baseSubpackets;
                },
                userSubpackets, // apply user-provided subpacket changes
                keyEncryptor)
                .build();
    }

    /**
     * Generate an OpenPGP key with a certification-capable primary key.
     * See {@link PGPKeyPairGenerator#generatePrimaryKey()} for the primary key type
     *
     * @return builder
     * @throws PGPException if the key cannot be generated
     */
    public WithPrimaryKey withPrimaryKey()
            throws PGPException
    {
        return withPrimaryKey((SignatureSubpacketsFunction) null);
    }

    public WithPrimaryKey withPrimaryKey(
            KeyPairGeneratorCallback keyGenCallback)
            throws PGPException
    {
        return withPrimaryKey(keyGenCallback, null);
    }

    /**
     * Generate an OpenPGP key with a certification-capable primary key.
     * See {@link PGPKeyPairGenerator#generatePrimaryKey()} for the primary key type
     * The key will carry a direct-key signature, whose subpackets can be modified by overriding the
     * given {@link SignatureSubpacketsFunction}.
     *
     * @param directKeySubpackets nullable callback to modify the direct-key signatures subpackets
     * @return builder
     * @throws PGPException if the key cannot be generated
     */
    public WithPrimaryKey withPrimaryKey(
            SignatureSubpacketsFunction directKeySubpackets)
            throws PGPException
    {
        return withPrimaryKey(
                PGPKeyPairGenerator::generatePrimaryKey,
                directKeySubpackets);
    }

    /**
     * Generate an OpenPGP key with a certification-capable primary key.
     * The {@link KeyPairGeneratorCallback} can be used to specify the primary key type.
     * The key will carry a direct-key signature, whose subpackets can be modified by overriding the
     * given {@link SignatureSubpacketsFunction}.
     *
     * @param keyGenCallback callback to specify the primary key type
     * @param directKeySubpackets nullable callback to modify the direct-key signatures subpackets
     * @return builder
     * @throws PGPException if the key cannot be generated
     */
    public WithPrimaryKey withPrimaryKey(
            KeyPairGeneratorCallback keyGenCallback,
            SignatureSubpacketsFunction directKeySubpackets)
            throws PGPException
    {
        return withPrimaryKey(keyGenCallback, directKeySubpackets, null);
    }

    /**
     * Generate an OpenPGP key with a certification-capable primary key.
     * The key will carry a direct-key signature, whose subpackets can be modified by overriding the
     * given {@link SignatureSubpacketsFunction}.
     *
     * @param primaryKeyPair primary key
     * @param directKeySubpackets nullable callback to modify the direct-key signatures subpackets
     * @return builder
     * @throws PGPException if the key cannot be generated
     */
    public WithPrimaryKey withPrimaryKey(
            PGPKeyPair primaryKeyPair,
            SignatureSubpacketsFunction directKeySubpackets)
            throws PGPException
    {
        return withPrimaryKey(
                primaryKeyPair,
                directKeySubpackets,
                null);
    }

    /**
     * Generate an OpenPGP key with a certification-capable primary key.
     * The {@link KeyPairGeneratorCallback} can be used to specify the primary key type.
     * The key will carry a direct-key signature, whose subpackets can be modified by overriding the
     * given {@link SignatureSubpacketsFunction}.
     * IMPORTANT: The custom primary key passphrase will only be used, if in the final step the key is retrieved
     * using {@link WithPrimaryKey#build()}.
     * If instead {@link WithPrimaryKey#build(char[])} is used, the key-specific passphrase is overwritten with the argument
     * passed into {@link WithPrimaryKey#build(char[])}.
     *
     * @param keyGenCallback callback to specify the primary key type
     * @param directKeySubpackets nullable callback to modify the direct-key signatures subpackets
     * @param passphrase nullable passphrase to protect the primary key with
     * @return builder
     * @throws PGPException if the key cannot be generated
     */
    public WithPrimaryKey withPrimaryKey(
            KeyPairGeneratorCallback keyGenCallback,
            SignatureSubpacketsFunction directKeySubpackets,
            char[] passphrase)
            throws PGPException
    {
        PGPKeyPair primaryKeyPair = keyGenCallback.generateFrom(
                impl.kpGenProvider.get(PublicKeyPacket.VERSION_6, conf.keyCreationTime));
        PBESecretKeyEncryptor keyEncryptor = impl.keyEncryptorBuilderProvider
                .build(passphrase, primaryKeyPair.getPublicKey().getPublicKeyPacket());
        return withPrimaryKey(primaryKeyPair, directKeySubpackets, keyEncryptor);
    }

    /**
     * Generate an OpenPGP key with a certification-capable primary key.
     * The {@link KeyPairGeneratorCallback} can be used to specify the primary key type.
     * The key will carry a direct-key signature, whose subpackets can be modified by overriding the
     * given {@link SignatureSubpacketsFunction}.
     * IMPORTANT: The custom keyEncryptor will only be used, if in the final step the key is retrieved
     * using {@link WithPrimaryKey#build()}.
     * If instead {@link WithPrimaryKey#build(char[])} is used, the key-specific encryptor is overwritten with
     * an encryptor built from the argument passed into {@link WithPrimaryKey#build(char[])}.
     *
     * @param primaryKeyPair primary key
     * @param directKeySubpackets nullable callback to modify the direct-key signatures subpackets
     * @param keyEncryptor nullable encryptor to protect the primary key with
     * @return builder
     * @throws PGPException if the key cannot be generated
     */
    public WithPrimaryKey withPrimaryKey(
            PGPKeyPair primaryKeyPair,
            SignatureSubpacketsFunction directKeySubpackets,
            PBESecretKeyEncryptor keyEncryptor)
            throws PGPException
    {
        if (!primaryKeyPair.getPublicKey().isMasterKey())
        {
            throw new IllegalArgumentException("Primary key MUST NOT consist of subkey packet.");
        }

        if (!PublicKeyUtils.isSigningAlgorithm(primaryKeyPair.getPublicKey().getAlgorithm()))
        {
            throw new PGPException("Primary key MUST use signing-capable algorithm.");
        }

        return primaryKeyWithDirectKeySig(
                primaryKeyPair,
                subpackets ->
                {
                    subpackets.setIssuerFingerprint(true, primaryKeyPair.getPublicKey());
                    subpackets.setSignatureCreationTime(conf.keyCreationTime);
                    subpackets.setKeyFlags(true, KeyFlags.CERTIFY_OTHER);
                    subpackets = DIRECT_KEY_SIGNATURE_SUBPACKETS.apply(subpackets);
                    subpackets.setKeyExpirationTime(false, 5 * SECONDS_PER_YEAR);
                    return subpackets;
                },
                directKeySubpackets,
                keyEncryptor);
    }

    /**
     * Specify the primary key and attach a direct-key signature.
     * The direct-key signature's subpackets will first be modified using the baseSubpackets callback, followed
     * by the customSubpackets callback.
     * If both baseSubpackets and customSubpackets are null, no direct-key signature will be attached.
     *
     * @param primaryKeyPair primary key pair
     * @param baseSubpackets base signature subpackets callback
     * @param customSubpackets user-provided signature subpackets callback
     * @param keyEncryptor key encryptor
     * @return builder
     * @throws PGPException if the key cannot be generated
     */
    private WithPrimaryKey primaryKeyWithDirectKeySig(
            PGPKeyPair primaryKeyPair,
            SignatureSubpacketsFunction baseSubpackets,
            SignatureSubpacketsFunction customSubpackets,
            PBESecretKeyEncryptor keyEncryptor)
            throws PGPException
    {
        if (baseSubpackets != null || customSubpackets != null)
        {
            // DK sig
            PGPSignatureGenerator dkSigGen = new PGPSignatureGenerator(
                    impl.contentSignerBuilderProvider.get(primaryKeyPair.getPublicKey()),
                    primaryKeyPair.getPublicKey());
            dkSigGen.init(PGPSignature.DIRECT_KEY, primaryKeyPair.getPrivateKey());

            PGPSignatureSubpacketGenerator subpackets = new PGPSignatureSubpacketGenerator();
            // application-dictated subpackets
            if (baseSubpackets != null)
            {
                subpackets = baseSubpackets.apply(subpackets);
            }

            // Allow the user to modify the direct-key signature subpackets
            if (customSubpackets != null)
            {
                subpackets = customSubpackets.apply(subpackets);
            }

            dkSigGen.setHashedSubpackets(subpackets.generate());

            PGPSignature dkSig = dkSigGen.generateCertification(primaryKeyPair.getPublicKey());
            primaryKeyPair = new PGPKeyPair(
                    PGPPublicKey.addCertification(primaryKeyPair.getPublicKey(), dkSig),
                    primaryKeyPair.getPrivateKey());
        }

        Key primaryKey = new Key(primaryKeyPair, keyEncryptor);

        return new WithPrimaryKey(impl, conf, primaryKey);
    }

    /**
     * Intermediate builder class.
     * Constructs an OpenPGP key from a specified primary key.
     */
    public static class WithPrimaryKey
    {

        private final Implementation impl;
        private final Configuration conf;
        private Key primaryKey;
        private final List<Key> subkeys = new ArrayList<Key>();

        /**
         * Builder.
         *
         * @param implementation cryptographic implementation
         * @param configuration key configuration
         * @param primaryKey specified primary key
         */
        private WithPrimaryKey(Implementation implementation, Configuration configuration, Key primaryKey)
        {
            this.impl = implementation;
            this.conf = configuration;
            this.primaryKey = primaryKey;
        }

        /**
         * Attach a User-ID with a positive certification to the key.
         *
         * @param userId user-id
         * @return builder
         * @throws PGPException if the user-id cannot be added
         */
        public WithPrimaryKey addUserId(String userId)
                throws PGPException
        {
            return addUserId(userId, null);
        }

        /**
         * Attach a User-ID with a positive certification to the key.
         * The subpackets of the user-id certification can be modified using the userIdSubpackets callback.
         *
         * @param userId user-id
         * @param userIdSubpackets callback to modify the certification subpackets
         * @return builder
         * @throws PGPException if the user-id cannot be added
         */
        public WithPrimaryKey addUserId(
                String userId,
                SignatureSubpacketsFunction userIdSubpackets)
                throws PGPException
        {
            return addUserId(userId, PGPSignature.POSITIVE_CERTIFICATION, userIdSubpackets);
        }

        /**
         * Attach a User-ID with a positive certification to the key.
         * The subpackets of the user-id certification can be modified using the userIdSubpackets callback.
         *
         * @param userId user-id
         * @param certificationType signature type
         * @param userIdSubpackets callback to modify the certification subpackets
         * @return builder
         * @throws PGPException if the user-id cannot be added
         */
        public WithPrimaryKey addUserId(
                String userId,
                int certificationType,
                SignatureSubpacketsFunction userIdSubpackets)
                throws PGPException
        {
            if (userId == null || userId.trim().isEmpty())
            {
                throw new IllegalArgumentException("User-ID cannot be null or empty.");
            }

            if (!PGPSignature.isCertification(certificationType))
            {
                throw new IllegalArgumentException("Signature type MUST be a certification type (0x10 - 0x13)");
            }

            PGPSignatureGenerator uidSigGen = new PGPSignatureGenerator(
                    impl.contentSignerBuilderProvider.get(primaryKey.pair.getPublicKey()),
                    primaryKey.pair.getPublicKey());
            uidSigGen.init(certificationType, primaryKey.pair.getPrivateKey());

            PGPSignatureSubpacketGenerator subpackets = new PGPSignatureSubpacketGenerator();
            subpackets.setIssuerFingerprint(true, primaryKey.pair.getPublicKey());
            subpackets.setSignatureCreationTime(conf.keyCreationTime);

            if (userIdSubpackets != null)
            {
                subpackets = userIdSubpackets.apply(subpackets);
            }
            uidSigGen.setHashedSubpackets(subpackets.generate());

            PGPSignature uidSig = uidSigGen.generateCertification(userId, primaryKey.pair.getPublicKey());
            PGPPublicKey pubKey = PGPPublicKey.addCertification(primaryKey.pair.getPublicKey(), userId, uidSig);
            primaryKey = new Key(new PGPKeyPair(pubKey, primaryKey.pair.getPrivateKey()), primaryKey.encryptor);

            return this;
        }

        /**
         * Add an encryption-capable subkey to the OpenPGP key.
         * See {@link PGPKeyPairGenerator#generateEncryptionSubkey()} for the key type.
         *
         * @return builder
         * @throws PGPException if the key cannot be generated
         */
        public WithPrimaryKey addEncryptionSubkey()
                throws PGPException
        {
            return addEncryptionSubkey(PGPKeyPairGenerator::generateEncryptionSubkey);
        }

        /**
         * Add an encryption-capable subkey to the OpenPGP key.
         * The type of the subkey can be decided by implementing the {@link KeyPairGeneratorCallback}.
         *
         * @param keyGenCallback callback to decide the encryption subkey type
         * @return builder
         * @throws PGPException if the key cannot be generated
         */
        public WithPrimaryKey addEncryptionSubkey(KeyPairGeneratorCallback keyGenCallback)
                throws PGPException
        {
            return addEncryptionSubkey(keyGenCallback, (char[]) null);
        }

        /**
         * Add an encryption-capable subkey to the OpenPGP key.
         * The type of the subkey can be decided by implementing the {@link KeyPairGeneratorCallback}.
         * The binding signature can be modified by implementing the {@link SignatureSubpacketsFunction}.
         *
         * @param generatorCallback callback to specify the encryption key type.
         * @param bindingSubpacketsCallback nullable callback to modify the binding signature subpackets
         * @return builder
         * @throws PGPException if the key cannot be generated
         */
        public WithPrimaryKey addEncryptionSubkey(
                KeyPairGeneratorCallback generatorCallback,
                SignatureSubpacketsFunction bindingSubpacketsCallback)
                throws PGPException
        {
            PGPKeyPairGenerator generator = impl.kpGenProvider.get(
                    primaryKey.pair.getPublicKey().getVersion(),
                    conf.keyCreationTime
            );
            PGPKeyPair subkey = generatorCallback.generateFrom(generator);

            return addEncryptionSubkey(subkey, bindingSubpacketsCallback, null);
        }

        /**
         * Add an encryption-capable subkey to the OpenPGP key.
         * The subkey will be protected using the provided subkey passphrase.
         * IMPORTANT: The custom subkey passphrase will only be used, if in the final step the key is retrieved
         * using {@link #build()}.
         * If instead {@link #build(char[])} is used, the key-specific passphrase is overwritten with the argument
         * passed into {@link #build(char[])}.
         * See {@link PGPKeyPairGenerator#generateEncryptionSubkey()} for the key type.
         *
         * @param passphrase nullable subkey passphrase
         * @return builder
         * @throws PGPException if the key cannot be generated
         */
        public WithPrimaryKey addEncryptionSubkey(char[] passphrase)
                throws PGPException
        {
            return addEncryptionSubkey(PGPKeyPairGenerator::generateEncryptionSubkey, passphrase);
        }

        /**
         * Add an encryption-capable subkey to the OpenPGP key.
         * The key type can be specified by overriding {@link KeyPairGeneratorCallback}.
         * The subkey will be protected using the provided subkey passphrase.
         * IMPORTANT: The custom subkey passphrase will only be used, if in the final step the key is retrieved
         * using {@link #build()}.
         * If instead {@link #build(char[])} is used, the key-specific passphrase is overwritten with the argument
         * passed into {@link #build(char[])}.
         *
         * @param keyGenCallback callback to specify the key type
         * @param passphrase nullable passphrase for the encryption subkey
         * @return builder
         * @throws PGPException if the key cannot be generated
         */
        public WithPrimaryKey addEncryptionSubkey(KeyPairGeneratorCallback keyGenCallback,
                                                  char[] passphrase)
                throws PGPException
        {
            return addEncryptionSubkey(keyGenCallback, null, passphrase);
        }

        /**
         * Add an encryption-capable subkey to the OpenPGP key.
         * The key type can be specified by overriding {@link KeyPairGeneratorCallback}.
         * The binding signatures subpackets can be modified by overriding the {@link SignatureSubpacketsFunction}.
         * The subkey will be protected using the provided subkey passphrase.
         * IMPORTANT: The custom subkey passphrase will only be used, if in the final step the key is retrieved
         * using {@link #build()}.
         * If instead {@link #build(char[])} is used, the key-specific passphrase is overwritten with the argument
         * passed into {@link #build(char[])}.
         *
         * @param keyGenCallback callback to specify the key type
         * @param bindingSignatureCallback nullable callback to modify the binding signature subpackets
         * @param passphrase nullable passphrase for the encryption subkey
         * @return builder
         * @throws PGPException if the key cannot be generated
         */
        public WithPrimaryKey addEncryptionSubkey(KeyPairGeneratorCallback keyGenCallback,
                                                  SignatureSubpacketsFunction bindingSignatureCallback,
                                                  char[] passphrase)
                throws PGPException
        {
            PGPKeyPair subkey = keyGenCallback.generateFrom(
                    impl.kpGenProvider.get(PublicKeyPacket.VERSION_6, conf.keyCreationTime));
            subkey = subkey.asSubkey(impl.keyFingerprintCalculator);
            PBESecretKeyEncryptor keyEncryptor = impl.keyEncryptorBuilderProvider.build(passphrase, subkey.getPublicKey().getPublicKeyPacket());
            return addEncryptionSubkey(subkey, bindingSignatureCallback, keyEncryptor);
        }


        /**
         * Add an encryption-capable subkey to the OpenPGP key.
         * IMPORTANT: The custom key encryptor will only be used, if in the final step the key is retrieved
         * using {@link #build()}.
         * If instead {@link #build(char[])} is used, the key-specific encryptor is overwritten with an encryptor
         * built from the argument passed into {@link #build(char[])}.
         *
         * @param encryptionSubkey encryption subkey
         * @param bindingSubpacketsCallback nullable callback to modify the subkey binding signature subpackets
         * @param keyEncryptor nullable encryptor to encrypt the encryption subkey
         * @return builder
         * @throws PGPException if the key cannot be generated
         */
        public WithPrimaryKey addEncryptionSubkey(
                PGPKeyPair encryptionSubkey,
                SignatureSubpacketsFunction bindingSubpacketsCallback,
                PBESecretKeyEncryptor keyEncryptor)
                throws PGPException
        {
            if (encryptionSubkey.getPublicKey().isMasterKey())
            {
                throw new IllegalArgumentException("Encryption subkey MUST NOT consist of a primary key packet.");
            }

            if (!PublicKeyUtils.isEncryptionAlgorithm(encryptionSubkey.getPublicKey().getAlgorithm()))
            {
                throw new PGPException("Encryption key MUST use encryption-capable algorithm.");
            }
            // generate binding signature
            PGPSignatureSubpacketGenerator subpackets = new PGPSignatureSubpacketGenerator();
            subpackets.setIssuerFingerprint(true, primaryKey.pair.getPublicKey());
            subpackets.setSignatureCreationTime(conf.keyCreationTime);
            subpackets = ENCRYPTION_SUBKEY_SUBPACKETS.apply(subpackets);

            // allow subpacket customization
            if (bindingSubpacketsCallback != null)
            {
                subpackets = bindingSubpacketsCallback.apply(subpackets);
            }

            PGPSignatureGenerator bindingSigGen = new PGPSignatureGenerator(
                    impl.contentSignerBuilderProvider.get(primaryKey.pair.getPublicKey()),
                    primaryKey.pair.getPublicKey());
            bindingSigGen.init(PGPSignature.SUBKEY_BINDING, primaryKey.pair.getPrivateKey());
            bindingSigGen.setHashedSubpackets(subpackets.generate());

            PGPSignature bindingSig = bindingSigGen.generateCertification(primaryKey.pair.getPublicKey(), encryptionSubkey.getPublicKey());
            PGPPublicKey publicSubkey = PGPPublicKey.addCertification(encryptionSubkey.getPublicKey(), bindingSig);
            Key subkey = new Key(new PGPKeyPair(publicSubkey, encryptionSubkey.getPrivateKey()), keyEncryptor);
            subkeys.add(subkey);
            return this;
        }

        /**
         * Add a signing-capable subkey to the OpenPGP key.
         * See {@link PGPKeyPairGenerator#generateSigningSubkey()} for the key type.
         *
         * @return builder
         * @throws PGPException if the key cannot be generated
         */
        public WithPrimaryKey addSigningSubkey()
                throws PGPException
        {
            return addSigningSubkey(PGPKeyPairGenerator::generateSigningSubkey);
        }

        /**
         * Add a signing-capable subkey to the OpenPGP key.
         * The key type can be specified by overriding {@link KeyPairGeneratorCallback}.
         *
         * @param keyGenCallback callback to specify the signing-subkey type
         * @return builder
         * @throws PGPException if the key cannot be generated
         */
        public WithPrimaryKey addSigningSubkey(KeyPairGeneratorCallback keyGenCallback)
                throws PGPException
        {
            return addSigningSubkey(keyGenCallback, null);
        }

        /**
         * Add a signing-capable subkey to the OpenPGP key.
         * See {@link PGPKeyPairGenerator#generateSigningSubkey()} for the key type.
         * IMPORTANT: The custom subkey passphrase will only be used, if in the final step the key is retrieved
         * using {@link #build()}.
         * If instead {@link #build(char[])} is used, the key-specific passphrase is overwritten with the argument
         * passed into {@link #build(char[])}.
         *
         * @param passphrase nullable passphrase
         * @return builder
         * @throws PGPException if the key cannot be generated
         */
        public WithPrimaryKey addSigningSubkey(char[] passphrase)
                throws PGPException
        {
            return addSigningSubkey(PGPKeyPairGenerator::generateSigningSubkey, passphrase);
        }

        /**
         * Add a signing-capable subkey to the OpenPGP key.
         * The signing-key type can be specified by overriding the {@link KeyPairGeneratorCallback}.
         * IMPORTANT: The custom subkey passphrase will only be used, if in the final step the key is retrieved
         * using {@link #build()}.
         * If instead {@link #build(char[])} is used, the key-specific passphrase is overwritten with the argument
         * passed into {@link #build(char[])}.
         *
         * @param keyGenCallback callback to specify the signing-key type
         * @param passphrase nullable passphrase
         * @return builder
         * @throws PGPException if the key cannot be generated
         */
        public WithPrimaryKey addSigningSubkey(KeyPairGeneratorCallback keyGenCallback,
                                               char[] passphrase)
                throws PGPException
        {
            return addSigningSubkey(keyGenCallback, null, null, passphrase);
        }

        /**
         * Add a signing-capable subkey to the OpenPGP key.
         * The signing-key type can be specified by overriding the {@link KeyPairGeneratorCallback}.
         * The contents of the binding signature(s) can be modified by overriding the respective
         * {@link SignatureSubpacketsFunction} instances.
         * IMPORTANT: The custom subkey passphrase will only be used, if in the final step the key is retrieved
         * using {@link #build()}.
         * If instead {@link #build(char[])} is used, the key-specific passphrase is overwritten with the argument
         * passed into {@link #build(char[])}.
         *
         * @param keyGenCallback callback to specify the signing-key type
         * @param bindingSignatureCallback callback to modify the contents of the signing subkey binding signature
         * @param backSignatureCallback callback to modify the contents of the embedded primary key binding signature
         * @param passphrase nullable passphrase
         * @return builder
         * @throws PGPException if the key cannot be generated
         */
        public WithPrimaryKey addSigningSubkey(KeyPairGeneratorCallback keyGenCallback,
                                               SignatureSubpacketsFunction bindingSignatureCallback,
                                               SignatureSubpacketsFunction backSignatureCallback,
                                               char[] passphrase)
                throws PGPException
        {
            PGPKeyPair subkey = keyGenCallback.generateFrom(impl.kpGenProvider.get(PublicKeyPacket.VERSION_6, conf.keyCreationTime));
            subkey = subkey.asSubkey(impl.keyFingerprintCalculator);
            PBESecretKeyEncryptor keyEncryptor = impl.keyEncryptorBuilderProvider.build(passphrase, subkey.getPublicKey().getPublicKeyPacket());
            return addSigningSubkey(subkey, bindingSignatureCallback, backSignatureCallback, keyEncryptor);
        }

        /**
         * Add a signing-capable subkey to the OpenPGP key.
         * The signing-key type can be specified by overriding the {@link KeyPairGeneratorCallback}.
         * The contents of the binding signature(s) can be modified by overriding the respective
         * {@link SignatureSubpacketsFunction} instances.
         * IMPORTANT: The custom key encryptor will only be used, if in the final step the key is retrieved
         * using {@link #build()}.
         * If instead {@link #build(char[])} is used, the key-specific encryptor is overwritten with an encryptor
         * built from the argument passed into {@link #build(char[])}.
         *
         * @param signingSubkey signing subkey
         * @param bindingSignatureCallback callback to modify the contents of the signing subkey binding signature
         * @param backSignatureCallback callback to modify the contents of the embedded primary key binding signature
         * @param keyEncryptor nullable encryptor to protect the signing subkey
         * @return builder
         * @throws PGPException if the key cannot be generated
         */
        public WithPrimaryKey addSigningSubkey(PGPKeyPair signingSubkey,
                                               SignatureSubpacketsFunction bindingSignatureCallback,
                                               SignatureSubpacketsFunction backSignatureCallback,
                                               PBESecretKeyEncryptor keyEncryptor)
                throws PGPException
        {
            if (signingSubkey.getPublicKey().isMasterKey())
            {
                throw new IllegalArgumentException("Signing subkey MUST NOT consist of primary key packet.");
            }

            if (!PublicKeyUtils.isSigningAlgorithm(signingSubkey.getPublicKey().getAlgorithm()))
            {
                throw new PGPException("Signing key MUST use signing-capable algorithm.");
            }

            PGPSignatureSubpacketGenerator backSigSubpackets = new PGPSignatureSubpacketGenerator();
            backSigSubpackets.setIssuerFingerprint(true, signingSubkey.getPublicKey());
            backSigSubpackets.setSignatureCreationTime(conf.keyCreationTime);
            if (backSignatureCallback != null)
            {
                backSigSubpackets = backSignatureCallback.apply(backSigSubpackets);
            }

            PGPSignatureSubpacketGenerator bindingSigSubpackets = new PGPSignatureSubpacketGenerator();
            bindingSigSubpackets.setIssuerFingerprint(true, primaryKey.pair.getPublicKey());
            bindingSigSubpackets.setSignatureCreationTime(conf.keyCreationTime);

            bindingSigSubpackets = SIGNING_SUBKEY_SUBPACKETS.apply(bindingSigSubpackets);

            PGPSignatureGenerator backSigGen = new PGPSignatureGenerator(
                    impl.contentSignerBuilderProvider.get(signingSubkey.getPublicKey()),
                    signingSubkey.getPublicKey());
            backSigGen.init(PGPSignature.PRIMARYKEY_BINDING, signingSubkey.getPrivateKey());
            backSigGen.setHashedSubpackets(backSigSubpackets.generate());
            PGPSignature backSig = backSigGen.generateCertification(
                    primaryKey.pair.getPublicKey(), signingSubkey.getPublicKey());

            try
            {
                bindingSigSubpackets.addEmbeddedSignature(false, backSig);
            }
            catch (IOException e)
            {
                throw new PGPException("Cannot embed back-signature.", e);
            }

            if (bindingSignatureCallback != null)
            {
                bindingSigSubpackets = bindingSignatureCallback.apply(bindingSigSubpackets);
            }

            PGPSignatureGenerator bindingSigGen = new PGPSignatureGenerator(
                    impl.contentSignerBuilderProvider.get(primaryKey.pair.getPublicKey()),
                    primaryKey.pair.getPublicKey());
            bindingSigGen.init(PGPSignature.SUBKEY_BINDING, primaryKey.pair.getPrivateKey());
            bindingSigGen.setHashedSubpackets(bindingSigSubpackets.generate());

            PGPSignature bindingSig = bindingSigGen.generateCertification(
                    primaryKey.pair.getPublicKey(), signingSubkey.getPublicKey());

            PGPPublicKey signingPubKey = PGPPublicKey.addCertification(signingSubkey.getPublicKey(), bindingSig);
            signingSubkey = new PGPKeyPair(signingPubKey, signingSubkey.getPrivateKey());
            subkeys.add(new Key(signingSubkey, keyEncryptor));

            return this;
        }

        /**
         * Build the {@link PGPSecretKeyRing OpenPGP key}, allowing individual passphrases for the subkeys.
         *
         * @return OpenPGP key
         * @throws PGPException if the key cannot be generated
         */
        public PGPSecretKeyRing build()
                throws PGPException
        {
            PGPSecretKey primarySecretKey = new PGPSecretKey(
                    primaryKey.pair.getPrivateKey(),
                    primaryKey.pair.getPublicKey(),
                    impl.digestCalculatorProvider.get(HashAlgorithmTags.SHA1),
                    true,
                    primaryKey.encryptor);
            List<PGPSecretKey> keys = new ArrayList<>();
            keys.add(primarySecretKey);

            for (Key key : subkeys)
            {
                PGPSecretKey subkey = new PGPSecretKey(
                        key.pair.getPrivateKey(),
                        key.pair.getPublicKey(),
                        impl.digestCalculatorProvider.get(HashAlgorithmTags.SHA1),
                        false,
                        key.encryptor);
                keys.add(subkey);
            }

            return new PGPSecretKeyRing(keys);
        }

        /**
         * Build the {@link PGPSecretKeyRing OpenPGP key} using a single passphrase used to protect all subkeys.
         * The passphrase will override whichever key protectors were specified in previous builder steps.
         *
         * @param passphrase nullable passphrase
         * @return OpenPGP key
         * @throws PGPException if the key cannot be generated
         */
        public PGPSecretKeyRing build(char[] passphrase)
                throws PGPException
        {
            PBESecretKeyEncryptor primaryKeyEncryptor = impl.keyEncryptorBuilderProvider
                    .build(passphrase, primaryKey.pair.getPublicKey().getPublicKeyPacket());
            sanitizeKeyEncryptor(primaryKeyEncryptor);
            PGPSecretKey primarySecretKey = new PGPSecretKey(
                    primaryKey.pair.getPrivateKey(),
                    primaryKey.pair.getPublicKey(),
                    impl.digestCalculatorProvider.get(HashAlgorithmTags.SHA1),
                    true,
                    primaryKeyEncryptor);
            List<PGPSecretKey> keys = new ArrayList<>();
            keys.add(primarySecretKey);

            for (Key key : subkeys)
            {
                PBESecretKeyEncryptor subkeyEncryptor = impl.keyEncryptorBuilderProvider
                        .build(passphrase, key.pair.getPublicKey().getPublicKeyPacket());
                sanitizeKeyEncryptor(subkeyEncryptor);
                PGPSecretKey subkey = new PGPSecretKey(
                        key.pair.getPrivateKey(),
                        key.pair.getPublicKey(),
                        impl.digestCalculatorProvider.get(HashAlgorithmTags.SHA1),
                        false,
                        subkeyEncryptor);
                keys.add(subkey);
            }

            if (passphrase != null)
            {
                Arrays.fill(passphrase, (char) 0);
            }

            return new PGPSecretKeyRing(keys);
        }

        protected void sanitizeKeyEncryptor(PBESecretKeyEncryptor keyEncryptor)
        {
            if (keyEncryptor == null)
            {
                // Unprotected is okay
                return;
            }

            S2K s2k = keyEncryptor.getS2K();
            if (s2k.getType() == S2K.SIMPLE || s2k.getType() == S2K.SALTED)
            {
                throw new IllegalArgumentException("S2K specifiers SIMPLE and SALTED are not allowed for secret key encryption.");
            }
            else if (s2k.getType() == S2K.ARGON_2)
            {
                if (keyEncryptor.getAeadAlgorithm() == 0)
                {
                    throw new IllegalArgumentException("Argon2 MUST be used with AEAD.");
                }
            }
        }
    }

    /**
     * Bundle implementation-specific provider classes.
     */
    private static class Implementation
    {
        final PGPKeyPairGeneratorProvider kpGenProvider;
        final PGPContentSignerBuilderProvider contentSignerBuilderProvider;
        final PGPDigestCalculatorProvider digestCalculatorProvider;
        final PBESecretKeyEncryptorFactory keyEncryptorBuilderProvider;
        final KeyFingerPrintCalculator keyFingerprintCalculator;

        public Implementation(PGPKeyPairGeneratorProvider keyPairGeneratorProvider,
                              PGPContentSignerBuilderProvider contentSignerBuilderProvider,
                              PGPDigestCalculatorProvider digestCalculatorProvider,
                              PBESecretKeyEncryptorFactory keyEncryptorBuilderProvider,
                              KeyFingerPrintCalculator keyFingerPrintCalculator)
        {
            this.kpGenProvider = keyPairGeneratorProvider;
            this.contentSignerBuilderProvider = contentSignerBuilderProvider;
            this.digestCalculatorProvider = digestCalculatorProvider;
            this.keyEncryptorBuilderProvider = keyEncryptorBuilderProvider;
            this.keyFingerprintCalculator = keyFingerPrintCalculator;
        }
    }

    /**
     * Bundle configuration-specific data.
     */
    private static class Configuration
    {
        final Date keyCreationTime;

        public Configuration(Date keyCreationTime)
        {
            this.keyCreationTime = keyCreationTime;
        }
    }

    /**
     * Tuple of a {@link PGPKeyPair} and (nullable) {@link PBESecretKeyEncryptor}.
     */
    private static class Key
    {
        private final PGPKeyPair pair;
        private final PBESecretKeyEncryptor encryptor;

        public Key(PGPKeyPair key, PBESecretKeyEncryptor encryptor)
        {
            this.pair = key;
            this.encryptor = encryptor;
        }
    }
}
