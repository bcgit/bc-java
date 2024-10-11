package org.bouncycastle.openpgp.api;

import org.bouncycastle.bcpg.AEADAlgorithmTags;
import org.bouncycastle.bcpg.CompressionAlgorithmTags;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyPacket;
import org.bouncycastle.bcpg.PublicKeyUtils;
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
    public static final int DEFAULT_SIGNATURE_HASH_ALGORITHM = HashAlgorithmTags.SHA3_512;

    private static final long SECONDS_PER_MINUTE = 60;
    private static final long SECONDS_PER_HOUR = 60 * SECONDS_PER_MINUTE;
    private static final long SECONDS_PER_DAY = 24 * SECONDS_PER_HOUR;
    private static final long SECONDS_PER_YEAR = 365 * SECONDS_PER_DAY;

    public static SignatureSubpacketsFunction DEFAULT_AEAD_ALGORITHM_PREFERENCES = subpackets ->
    {
        subpackets.removePacketsOfType(SignatureSubpacketTags.PREFERRED_AEAD_ALGORITHMS);
        subpackets.setPreferredAEADCiphersuites(PreferredAEADCiphersuites.builder(false)
                .addCombination(SymmetricKeyAlgorithmTags.AES_256, AEADAlgorithmTags.OCB)
                .addCombination(SymmetricKeyAlgorithmTags.AES_192, AEADAlgorithmTags.OCB)
                .addCombination(SymmetricKeyAlgorithmTags.AES_128, AEADAlgorithmTags.OCB));
        return subpackets;
    };

    public static SignatureSubpacketsFunction DEFAULT_SYMMETRIC_KEY_PREFERENCES = subpackets ->
    {
        subpackets.removePacketsOfType(SignatureSubpacketTags.PREFERRED_SYM_ALGS);
        subpackets.setPreferredSymmetricAlgorithms(false, new int[] {
                SymmetricKeyAlgorithmTags.AES_256, SymmetricKeyAlgorithmTags.AES_192, SymmetricKeyAlgorithmTags.AES_128
        });
        return subpackets;
    };

    public static SignatureSubpacketsFunction DEFAULT_HASH_ALGORITHM_PREFERENCES = subpackets ->
    {
        subpackets.removePacketsOfType(SignatureSubpacketTags.PREFERRED_HASH_ALGS);
        subpackets.setPreferredHashAlgorithms(false, new int[] {
                HashAlgorithmTags.SHA3_512, HashAlgorithmTags.SHA3_256,
                HashAlgorithmTags.SHA512, HashAlgorithmTags.SHA384, HashAlgorithmTags.SHA256
        });
        return subpackets;
    };

    public static SignatureSubpacketsFunction DEFAULT_COMPRESSION_ALGORITHM_PREFERENCES = subpackets ->
    {
        subpackets.removePacketsOfType(SignatureSubpacketTags.PREFERRED_COMP_ALGS);
        subpackets.setPreferredCompressionAlgorithms(false, new int[] {
                CompressionAlgorithmTags.UNCOMPRESSED, CompressionAlgorithmTags.ZIP,
                CompressionAlgorithmTags.ZLIB, CompressionAlgorithmTags.BZIP2
        });
        return subpackets;
    };

    public static SignatureSubpacketsFunction DEFAULT_FEATURES = subpackets ->
    {
        subpackets.removePacketsOfType(SignatureSubpacketTags.FEATURES);
        subpackets.setFeature(false, (byte) (Features.FEATURE_MODIFICATION_DETECTION | Features.FEATURE_SEIPD_V2));
        return subpackets;
    };

    public static SignatureSubpacketsFunction SIGNING_SUBKEY_SUBPACKETS = subpackets ->
    {
        subpackets.removePacketsOfType(SignatureSubpacketTags.KEY_FLAGS);
        subpackets.setKeyFlags(true, KeyFlags.SIGN_DATA);
        return subpackets;
    };

    public static SignatureSubpacketsFunction DIRECT_KEY_SIGNATURE_SUBPACKETS = subpackets ->
    {
        subpackets = DEFAULT_FEATURES.apply(subpackets);
        subpackets = DEFAULT_HASH_ALGORITHM_PREFERENCES.apply(subpackets);
        subpackets = DEFAULT_COMPRESSION_ALGORITHM_PREFERENCES.apply(subpackets);
        subpackets = DEFAULT_SYMMETRIC_KEY_PREFERENCES.apply(subpackets);
        subpackets = DEFAULT_AEAD_ALGORITHM_PREFERENCES.apply(subpackets);
        return subpackets;
    };

    private final Implementation impl;
    private final Configuration conf;

    /**
     * Generate a new OpenPGP key generator for v6 keys.
     *
     * @param kpGenProvider key pair generator provider
     * @param contentSignerBuilderProvider content signer builder provider
     * @param digestCalculatorProvider digest calculator provider
     * @param keyEncryptionBuilderProvider secret key encryption builder provider (AEAD)
     * @param creationTime key creation time
     */
    public OpenPGPV6KeyGenerator(
            PGPKeyPairGeneratorProvider kpGenProvider,
            PGPContentSignerBuilderProvider contentSignerBuilderProvider,
            PGPDigestCalculatorProvider digestCalculatorProvider,
            PBESecretKeyEncryptorFactory keyEncryptionBuilderProvider,
            Date creationTime)
    {
        this.impl = new Implementation(kpGenProvider, contentSignerBuilderProvider, digestCalculatorProvider, keyEncryptionBuilderProvider);
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
     * Generate a sign-only OpenPGP key.
     * The key consists of a single, user-id-less Ed25519 key, which is capable of signing and certifying.
     * It carries a single direct-key signature with signing-related preferences.
     *
     * @return sign-only (+certify) OpenPGP key
     * @throws PGPException if the key cannot be generated
     */
    public PGPSecretKeyRing signOnlyKey()
            throws PGPException
    {
        return signOnlyKey(null);
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
        PGPKeyPair primaryKey = impl.kpGenProvider.get(PublicKeyPacket.VERSION_6, conf.creationTime)
                .generatePrimaryKey();
        PBESecretKeyEncryptor encryptor = impl.keyEncryptorBuilderProvider
                .build(passphrase, primaryKey.getPublicKey().getPublicKeyPacket());
        return signOnlyKey(primaryKey, encryptor, userSubpackets);
    }

    /**
     * Generate a sign-only OpenPGP key.
     * The key consists of a single, user-id-less primary key, which is capable of signing and certifying.
     * It carries a single direct-key signature with signing-related preferences whose subpackets can be
     * modified by providing a {@link SignatureSubpacketsFunction}.
     *
     * @param primaryKey signing-capable primary key
     * @param keyEncryptor nullable encryptor to protect the primary key with
     * @param userSubpackets callback to modify the direct-key signature subpackets with
     * @return sign-only (+certify) OpenPGP key
     * @throws PGPException if the key cannot be generated
     */
    public PGPSecretKeyRing signOnlyKey(
            PGPKeyPair primaryKey,
            PBESecretKeyEncryptor keyEncryptor,
            SignatureSubpacketsFunction userSubpackets)
            throws PGPException
    {
        return primaryKeyWithDirectKeySig(primaryKey,
                baseSubpackets ->
                {
                    // remove unrelated subpackets not needed for sign-only keys
                    baseSubpackets.removePacketsOfType(SignatureSubpacketTags.PREFERRED_AEAD_ALGORITHMS);
                    baseSubpackets.removePacketsOfType(SignatureSubpacketTags.PREFERRED_SYM_ALGS);
                    baseSubpackets.removePacketsOfType(SignatureSubpacketTags.PREFERRED_COMP_ALGS);

                    // replace key flags to add SIGN_DATA
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
        return withPrimaryKey(null);
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
     * @param keyPair primary key
     * @param directKeySubpackets nullable callback to modify the direct-key signatures subpackets
     * @return builder
     * @throws PGPException if the key cannot be generated
     */
    public WithPrimaryKey withPrimaryKey(
            PGPKeyPair keyPair,
            SignatureSubpacketsFunction directKeySubpackets)
            throws PGPException
    {
        return withPrimaryKey(
                keyPair,
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
        PGPKeyPair pkPair = keyGenCallback.generateFrom(
                impl.kpGenProvider.get(PublicKeyPacket.VERSION_6, conf.creationTime));
        PBESecretKeyEncryptor keyEncryptor = impl.keyEncryptorBuilderProvider
                .build(passphrase, pkPair.getPublicKey().getPublicKeyPacket());
        return withPrimaryKey(pkPair, directKeySubpackets, keyEncryptor);
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
     * @param keyPair primary key
     * @param directKeySubpackets nullable callback to modify the direct-key signatures subpackets
     * @param keyEncryptor nullable encryptor to protect the primary key with
     * @return builder
     * @throws PGPException if the key cannot be generated
     */
    public WithPrimaryKey withPrimaryKey(
            PGPKeyPair keyPair,
            SignatureSubpacketsFunction directKeySubpackets,
            PBESecretKeyEncryptor keyEncryptor)
            throws PGPException
    {
        if (!PublicKeyUtils.isSigningAlgorithm(keyPair.getPublicKey().getAlgorithm()))
        {
            throw new PGPException("Primary key MUST use signing-capable algorithm.");
        }

        return primaryKeyWithDirectKeySig(
                keyPair,
                subpackets ->
                {
                    subpackets.setIssuerFingerprint(true, keyPair.getPublicKey());
                    subpackets.setSignatureCreationTime(conf.creationTime);
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
     * @param encryptor key encryptor
     * @return builder
     * @throws PGPException if the key cannot be generated
     */
    private WithPrimaryKey primaryKeyWithDirectKeySig(
            PGPKeyPair primaryKeyPair,
            SignatureSubpacketsFunction baseSubpackets,
            SignatureSubpacketsFunction customSubpackets,
            PBESecretKeyEncryptor encryptor)
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

        Key primaryKey = new Key(primaryKeyPair, encryptor);

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
            subpackets.setSignatureCreationTime(conf.creationTime);

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
                    conf.creationTime
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
            PGPKeyPair subkey = keyGenCallback.generateFrom(impl.kpGenProvider.get(PublicKeyPacket.VERSION_6, conf.creationTime));
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
         * @param encryptor nullable encryptor to encrypt the encryption subkey
         * @return builder
         * @throws PGPException if the key cannot be generated
         */
        public WithPrimaryKey addEncryptionSubkey(
                PGPKeyPair encryptionSubkey,
                SignatureSubpacketsFunction bindingSubpacketsCallback,
                PBESecretKeyEncryptor encryptor)
                throws PGPException
        {
            if (!PublicKeyUtils.isEncryptionAlgorithm(encryptionSubkey.getPublicKey().getAlgorithm()))
            {
                throw new PGPException("Encryption key MUST use encryption-capable algorithm.");
            }
            // generate binding signature
            PGPSignatureSubpacketGenerator subpackets = new PGPSignatureSubpacketGenerator();
            subpackets.setKeyFlags(false, KeyFlags.ENCRYPT_STORAGE | KeyFlags.ENCRYPT_COMMS);
            subpackets.setIssuerFingerprint(true, primaryKey.pair.getPublicKey());
            subpackets.setSignatureCreationTime(conf.creationTime);

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
            Key subkey = new Key(new PGPKeyPair(publicSubkey, encryptionSubkey.getPrivateKey()), encryptor);
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
         * @param generatorCallback callback to specify the signing-subkey type
         * @return builder
         * @throws PGPException if the key cannot be generated
         */
        public WithPrimaryKey addSigningSubkey(KeyPairGeneratorCallback generatorCallback)
                throws PGPException
        {
            return addSigningSubkey(generatorCallback, null);
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
            PGPKeyPair subkey = keyGenCallback.generateFrom(impl.kpGenProvider.get(PublicKeyPacket.VERSION_6, conf.creationTime));
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
         * @param signingKey signing subkey
         * @param bindingSignatureCallback callback to modify the contents of the signing subkey binding signature
         * @param backSignatureCallback callback to modify the contents of the embedded primary key binding signature
         * @param keyEncryptor nullable encryptor to protect the signing subkey
         * @return builder
         * @throws PGPException if the key cannot be generated
         */
        public WithPrimaryKey addSigningSubkey(PGPKeyPair signingKey,
                                               SignatureSubpacketsFunction bindingSignatureCallback,
                                               SignatureSubpacketsFunction backSignatureCallback,
                                               PBESecretKeyEncryptor keyEncryptor)
                throws PGPException
        {
            if (!PublicKeyUtils.isSigningAlgorithm(signingKey.getPublicKey().getAlgorithm()))
            {
                throw new PGPException("Signing key MUST use signing-capable algorithm.");
            }

            PGPSignatureSubpacketGenerator backSigSubpackets = new PGPSignatureSubpacketGenerator();
            backSigSubpackets.setIssuerFingerprint(true, signingKey.getPublicKey());
            backSigSubpackets.setSignatureCreationTime(conf.creationTime);
            if (backSignatureCallback != null)
            {
                backSigSubpackets = backSignatureCallback.apply(backSigSubpackets);
            }

            PGPSignatureSubpacketGenerator bindingSigSubpackets = new PGPSignatureSubpacketGenerator();
            bindingSigSubpackets.setIssuerFingerprint(true, primaryKey.pair.getPublicKey());
            bindingSigSubpackets.setSignatureCreationTime(conf.creationTime);

            bindingSigSubpackets = SIGNING_SUBKEY_SUBPACKETS.apply(bindingSigSubpackets);

            PGPSignatureGenerator backSigGen = new PGPSignatureGenerator(
                    impl.contentSignerBuilderProvider.get(signingKey.getPublicKey()),
                    signingKey.getPublicKey());
            backSigGen.init(PGPSignature.PRIMARYKEY_BINDING, signingKey.getPrivateKey());
            backSigGen.setHashedSubpackets(backSigSubpackets.generate());
            PGPSignature backSig = backSigGen.generateCertification(
                    primaryKey.pair.getPublicKey(), signingKey.getPublicKey());

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
                    primaryKey.pair.getPublicKey(), signingKey.getPublicKey());

            PGPPublicKey signingPubKey = PGPPublicKey.addCertification(signingKey.getPublicKey(), bindingSig);
            signingKey = new PGPKeyPair(signingPubKey, signingKey.getPrivateKey());
            subkeys.add(new Key(signingKey, keyEncryptor));

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
                passphrase = null;
            }

            return new PGPSecretKeyRing(keys);
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

        public Implementation(PGPKeyPairGeneratorProvider keyPairGeneratorProvider,
                              PGPContentSignerBuilderProvider contentSignerBuilderProvider,
                              PGPDigestCalculatorProvider digestCalculatorProvider,
                              PBESecretKeyEncryptorFactory keyEncryptorBuilderProvider)
        {
            this.kpGenProvider = keyPairGeneratorProvider;
            this.contentSignerBuilderProvider = contentSignerBuilderProvider;
            this.digestCalculatorProvider = digestCalculatorProvider;
            this.keyEncryptorBuilderProvider = keyEncryptorBuilderProvider;
        }
    }

    /**
     * Bundle configuration-specific data.
     */
    private static class Configuration
    {
        final Date creationTime;

        public Configuration(Date creationTime)
        {
            this.creationTime = creationTime;
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
