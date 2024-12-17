package org.bouncycastle.openpgp.api;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;
import java.util.List;

import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyPacket;
import org.bouncycastle.bcpg.PublicKeyUtils;
import org.bouncycastle.bcpg.PublicSubkeyPacket;
import org.bouncycastle.bcpg.S2K;
import org.bouncycastle.bcpg.SignatureSubpacketTags;
import org.bouncycastle.bcpg.sig.KeyFlags;
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

/**
 * High-level generator class for OpenPGP v6 keys.
 */
public class OpenPGPV6KeyGenerator
    extends AbstractOpenPGPKeySignatureGenerator
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


    private final OpenPGPImplementation implementationProvider;
    private final Configuration configuration; // contains BC or JCA/JCE implementations

    public OpenPGPV6KeyGenerator(OpenPGPImplementation implementationProvider,
                                 int signatureHashAlgorithmId,
                                 boolean aead,
                                 Date creationTime) throws PGPException {
        this(
                implementationProvider,
                implementationProvider.pgpKeyPairGeneratorProvider(),
                implementationProvider.pgpContentSignerBuilderProvider(signatureHashAlgorithmId),
                implementationProvider.pgpDigestCalculatorProvider(),
                implementationProvider.pbeSecretKeyEncryptorFactory(aead),
                implementationProvider.keyFingerPrintCalculator(),
                creationTime
        );
    }

    /**
     * Generate a new OpenPGP key generator for v6 keys.
     *
     * @param kpGenProvider                key pair generator provider
     * @param contentSignerBuilderProvider content signer builder provider
     * @param digestCalculatorProvider     digest calculator provider
     * @param keyEncryptionBuilderProvider secret key encryption builder provider (AEAD)
     * @param keyFingerPrintCalculator     calculator for key fingerprints
     * @param creationTime                 key creation time
     */
    public OpenPGPV6KeyGenerator(
        OpenPGPImplementation implementationProvider,
        PGPKeyPairGeneratorProvider kpGenProvider,
        PGPContentSignerBuilderProvider contentSignerBuilderProvider,
        PGPDigestCalculatorProvider digestCalculatorProvider,
        PBESecretKeyEncryptorFactory keyEncryptionBuilderProvider,
        KeyFingerPrintCalculator keyFingerPrintCalculator,
        Date creationTime)
    {
        this.implementationProvider = implementationProvider;
        this.configuration = new Configuration(creationTime, kpGenProvider, contentSignerBuilderProvider, digestCalculatorProvider, keyEncryptionBuilderProvider, keyFingerPrintCalculator);
    }

    /**
     * Generate an OpenPGP key consisting of a certify-only primary key,
     * a dedicated signing-subkey and dedicated encryption-subkey.
     * The key will carry the provided user-id and be protected using the provided passphrase.
     * See {@link PGPKeyPairGenerator#generatePrimaryKey()} for the primary key type,
     * {@link PGPKeyPairGenerator#generateSigningSubkey()} for the signing-subkey type and
     * {@link PGPKeyPairGenerator#generateEncryptionSubkey()} for the encryption-subkey key type.
     *
     * @param userId     user id
     * @param passphrase nullable passphrase.
     * @return OpenPGP key
     * @throws PGPException if the key cannot be generated
     */
    public OpenPGPKey classicKey(String userId, char[] passphrase)
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
     * @param userId     user id
     * @param passphrase nullable passphrase
     * @return OpenPGP key
     * @throws PGPException if the key cannot be generated
     */
    public OpenPGPKey ed25519x25519Key(String userId, char[] passphrase)
        throws PGPException
    {
        return withPrimaryKey(new KeyPairGeneratorCallback()
        {
            public PGPKeyPair generateFrom(PGPKeyPairGenerator generator)
                throws PGPException
            {
                return generator.generateEd25519KeyPair();
            }
        })
            .addSigningSubkey(new KeyPairGeneratorCallback()
            {
                public PGPKeyPair generateFrom(PGPKeyPairGenerator generator)
                    throws PGPException
                {
                    return generator.generateEd25519KeyPair();
                }
            })
            .addEncryptionSubkey(new KeyPairGeneratorCallback()
            {
                public PGPKeyPair generateFrom(PGPKeyPairGenerator generator)
                    throws PGPException
                {
                    return generator.generateX25519KeyPair();
                }
            })
            .addUserId(userId)
            .build(passphrase);
    }


    /**
     * Generate an OpenPGP key consisting of an Ed448 certify-only primary key,
     * a dedicated Ed448 sign-only subkey and dedicated X448 encryption-only subkey.
     * The key will carry the provided user-id and be protected using the provided passphrase.
     *
     * @param userId     user id
     * @param passphrase nullable passphrase
     * @return OpenPGP key
     * @throws PGPException if the key cannot be generated
     */
    public OpenPGPKey ed448x448Key(String userId, char[] passphrase)
        throws PGPException
    {
        return withPrimaryKey(new KeyPairGeneratorCallback()
        {
            public PGPKeyPair generateFrom(PGPKeyPairGenerator generator)
                throws PGPException
            {
                return generator.generateEd448KeyPair();
            }
        })
            .addSigningSubkey(new KeyPairGeneratorCallback()
            {
                public PGPKeyPair generateFrom(PGPKeyPairGenerator generator)
                    throws PGPException
                {
                    return generator.generateEd448KeyPair();
                }
            })
            .addEncryptionSubkey(new KeyPairGeneratorCallback()
            {
                public PGPKeyPair generateFrom(PGPKeyPairGenerator generator)
                    throws PGPException
                {
                    return generator.generateX448KeyPair();
                }
            })
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
    public OpenPGPKey signOnlyKey(char[] passphrase)
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
     * @param passphrase     nullable passphrase to protect the key with
     * @param userSubpackets callback to modify the direct-key signature subpackets with
     * @return sign-only (+certify) OpenPGP key
     * @throws PGPException if the key cannot be generated
     */
    public OpenPGPKey signOnlyKey(
        char[] passphrase,
        SignatureSubpacketsFunction userSubpackets)
        throws PGPException
    {
        PGPKeyPair primaryKeyPair = configuration.kpGenProvider.get(PublicKeyPacket.VERSION_6, configuration.keyCreationTime)
            .generatePrimaryKey();
        PBESecretKeyEncryptor encryptor = configuration.keyEncryptorBuilderProvider
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
     * @param keyEncryptor   nullable encryptor to protect the primary key with
     * @param userSubpackets callback to modify the direct-key signature subpackets with
     * @return sign-only (+certify) OpenPGP key
     * @throws PGPException if the key cannot be generated
     */
    public OpenPGPKey signOnlyKey(
        PGPKeyPair primaryKeyPair,
        PBESecretKeyEncryptor keyEncryptor,
        SignatureSubpacketsFunction userSubpackets)
        throws PGPException
    {
        if (primaryKeyPair.getPublicKey().getPublicKeyPacket() instanceof PublicSubkeyPacket)
        {
            throw new IllegalArgumentException("Primary key MUST NOT consist of subkey packet.");
        }

        return primaryKeyWithDirectKeySig(primaryKeyPair,
            new SignatureSubpacketsFunction()
            {
                public PGPSignatureSubpacketGenerator apply(PGPSignatureSubpacketGenerator baseSubpackets)
                {
                    // remove unrelated subpackets not needed for sign-only keys
                    baseSubpackets.removePacketsOfType(SignatureSubpacketTags.PREFERRED_AEAD_ALGORITHMS);
                    baseSubpackets.removePacketsOfType(SignatureSubpacketTags.PREFERRED_SYM_ALGS);
                    baseSubpackets.removePacketsOfType(SignatureSubpacketTags.PREFERRED_COMP_ALGS);

                    // replace key flags -> CERTIFY_OTHER|SIGN_DATA
                    baseSubpackets.removePacketsOfType(SignatureSubpacketTags.KEY_FLAGS);
                    baseSubpackets.setKeyFlags(true, KeyFlags.CERTIFY_OTHER | KeyFlags.SIGN_DATA);
                    return baseSubpackets;
                }
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
        return withPrimaryKey((SignatureSubpacketsFunction)null);
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
            new KeyPairGeneratorCallback()
            {
                public PGPKeyPair generateFrom(PGPKeyPairGenerator generator)
                    throws PGPException
                {
                    return generator.generatePrimaryKey();
                }
            },
            directKeySubpackets);
    }

    /**
     * Generate an OpenPGP key with a certification-capable primary key.
     * The {@link KeyPairGeneratorCallback} can be used to specify the primary key type.
     * The key will carry a direct-key signature, whose subpackets can be modified by overriding the
     * given {@link SignatureSubpacketsFunction}.
     *
     * @param keyGenCallback      callback to specify the primary key type
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
     * @param primaryKeyPair      primary key
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
     * @param keyGenCallback      callback to specify the primary key type
     * @param directKeySubpackets nullable callback to modify the direct-key signatures subpackets
     * @param passphrase          nullable passphrase to protect the primary key with
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
            configuration.kpGenProvider.get(PublicKeyPacket.VERSION_6, configuration.keyCreationTime));
        PBESecretKeyEncryptor keyEncryptor = configuration.keyEncryptorBuilderProvider
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
     * @param primaryKeyPair      primary key
     * @param directKeySubpackets nullable callback to modify the direct-key signatures subpackets
     * @param keyEncryptor        nullable encryptor to protect the primary key with
     * @return builder
     * @throws PGPException if the key cannot be generated
     */
    public WithPrimaryKey withPrimaryKey(
        final PGPKeyPair primaryKeyPair,
        SignatureSubpacketsFunction directKeySubpackets,
        PBESecretKeyEncryptor keyEncryptor)
        throws PGPException
    {
        if (primaryKeyPair.getPublicKey().getPublicKeyPacket() instanceof PublicSubkeyPacket)
        {
            throw new IllegalArgumentException("Primary key MUST NOT consist of subkey packet.");
        }

        if (!PublicKeyUtils.isSigningAlgorithm(primaryKeyPair.getPublicKey().getAlgorithm()))
        {
            throw new PGPException("Primary key MUST use signing-capable algorithm.");
        }

        return primaryKeyWithDirectKeySig(
            primaryKeyPair,
            new SignatureSubpacketsFunction()
            {
                public PGPSignatureSubpacketGenerator apply(PGPSignatureSubpacketGenerator subpackets)
                {
                    subpackets.setIssuerFingerprint(true, primaryKeyPair.getPublicKey());
                    subpackets.setSignatureCreationTime(configuration.keyCreationTime);
                    subpackets.setKeyFlags(true, KeyFlags.CERTIFY_OTHER);
                    subpackets = directKeySignatureSubpackets.apply(subpackets);
                    subpackets.setKeyExpirationTime(false, 5 * SECONDS_PER_YEAR);
                    return subpackets;
                }
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
     * @param primaryKeyPair   primary key pair
     * @param baseSubpackets   base signature subpackets callback
     * @param customSubpackets user-provided signature subpackets callback
     * @param keyEncryptor     key encryptor
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
                configuration.contentSignerBuilderProvider.get(primaryKeyPair.getPublicKey()),
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

        return new WithPrimaryKey(implementationProvider, configuration, primaryKey);
    }

    /**
     * Intermediate builder class.
     * Constructs an OpenPGP key from a specified primary key.
     */
    public class WithPrimaryKey
    {
        private final OpenPGPImplementation implementation;
        private final Configuration configuration;
        private Key primaryKey;
        private final List<Key> subkeys = new ArrayList<Key>();

        /**
         * Builder.
         *
         * @param implementation cryptographic implementation
         * @param primaryKey     specified primary key
         */
        private WithPrimaryKey(OpenPGPImplementation implementation, Configuration configuration, Key primaryKey)
        {
            this.implementation = implementation;
            this.configuration = configuration;
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
         * @param userId           user-id
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
         * @param userId            user-id
         * @param certificationType signature type
         * @param userIdSubpackets  callback to modify the certification subpackets
         * @return builder
         * @throws PGPException if the user-id cannot be added
         */
        public WithPrimaryKey addUserId(
            String userId,
            int certificationType,
            SignatureSubpacketsFunction userIdSubpackets)
            throws PGPException
        {
            if (userId == null || userId.trim().length() == 0)
            {
                throw new IllegalArgumentException("User-ID cannot be null or empty.");
            }

            if (!PGPSignature.isCertification(certificationType))
            {
                throw new IllegalArgumentException("Signature type MUST be a certification type (0x10 - 0x13)");
            }

            PGPSignatureGenerator uidSigGen = new PGPSignatureGenerator(
                configuration.contentSignerBuilderProvider.get(primaryKey.pair.getPublicKey()),
                primaryKey.pair.getPublicKey());
            uidSigGen.init(certificationType, primaryKey.pair.getPrivateKey());

            PGPSignatureSubpacketGenerator subpackets = new PGPSignatureSubpacketGenerator();
            subpackets.setIssuerFingerprint(true, primaryKey.pair.getPublicKey());
            subpackets.setSignatureCreationTime(configuration.keyCreationTime);

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
            return addEncryptionSubkey(new KeyPairGeneratorCallback()
            {
                public PGPKeyPair generateFrom(PGPKeyPairGenerator generator)
                    throws PGPException
                {
                    return generator.generateEncryptionSubkey();
                }
            });
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
            return addEncryptionSubkey(keyGenCallback, (char[])null);
        }

        /**
         * Add an encryption-capable subkey to the OpenPGP key.
         * The type of the subkey can be decided by implementing the {@link KeyPairGeneratorCallback}.
         * The binding signature can be modified by implementing the {@link SignatureSubpacketsFunction}.
         *
         * @param generatorCallback         callback to specify the encryption key type.
         * @param bindingSubpacketsCallback nullable callback to modify the binding signature subpackets
         * @return builder
         * @throws PGPException if the key cannot be generated
         */
        public WithPrimaryKey addEncryptionSubkey(
            KeyPairGeneratorCallback generatorCallback,
            SignatureSubpacketsFunction bindingSubpacketsCallback)
            throws PGPException
        {
            PGPKeyPairGenerator generator = configuration.kpGenProvider.get(
                primaryKey.pair.getPublicKey().getVersion(),
                configuration.keyCreationTime
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
            return addEncryptionSubkey(new KeyPairGeneratorCallback()
            {
                public PGPKeyPair generateFrom(PGPKeyPairGenerator generator)
                    throws PGPException
                {
                    return generator.generateEncryptionSubkey();
                }
            }, passphrase);
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
         * @param passphrase     nullable passphrase for the encryption subkey
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
         * @param keyGenCallback           callback to specify the key type
         * @param bindingSignatureCallback nullable callback to modify the binding signature subpackets
         * @param passphrase               nullable passphrase for the encryption subkey
         * @return builder
         * @throws PGPException if the key cannot be generated
         */
        public WithPrimaryKey addEncryptionSubkey(KeyPairGeneratorCallback keyGenCallback,
                                                  SignatureSubpacketsFunction bindingSignatureCallback,
                                                  char[] passphrase)
            throws PGPException
        {
            PGPKeyPair subkey = keyGenCallback.generateFrom(
                configuration.kpGenProvider.get(PublicKeyPacket.VERSION_6, configuration.keyCreationTime));
            subkey = subkey.asSubkey(configuration.keyFingerprintCalculator);
            PBESecretKeyEncryptor keyEncryptor = configuration.keyEncryptorBuilderProvider.build(passphrase, subkey.getPublicKey().getPublicKeyPacket());
            return addEncryptionSubkey(subkey, bindingSignatureCallback, keyEncryptor);
        }


        /**
         * Add an encryption-capable subkey to the OpenPGP key.
         * IMPORTANT: The custom key encryptor will only be used, if in the final step the key is retrieved
         * using {@link #build()}.
         * If instead {@link #build(char[])} is used, the key-specific encryptor is overwritten with an encryptor
         * built from the argument passed into {@link #build(char[])}.
         *
         * @param encryptionSubkey          encryption subkey
         * @param bindingSubpacketsCallback nullable callback to modify the subkey binding signature subpackets
         * @param keyEncryptor              nullable encryptor to encrypt the encryption subkey
         * @return builder
         * @throws PGPException if the key cannot be generated
         */
        public WithPrimaryKey addEncryptionSubkey(
            PGPKeyPair encryptionSubkey,
            SignatureSubpacketsFunction bindingSubpacketsCallback,
            PBESecretKeyEncryptor keyEncryptor)
            throws PGPException
        {
            if (!(encryptionSubkey.getPublicKey().getPublicKeyPacket() instanceof PublicSubkeyPacket))
            {
                throw new IllegalArgumentException("Encryption subkey MUST NOT consist of a primary key packet.");
            }

            if (!encryptionSubkey.getPublicKey().isEncryptionKey())
            {
                throw new PGPException("Encryption key MUST use encryption-capable algorithm.");
            }
            // generate binding signature
            PGPSignatureSubpacketGenerator subpackets = new PGPSignatureSubpacketGenerator();
            subpackets.setIssuerFingerprint(true, primaryKey.pair.getPublicKey());
            subpackets.setSignatureCreationTime(configuration.keyCreationTime);
            subpackets = encryptionSubkeySubpackets.apply(subpackets);

            // allow subpacket customization
            PGPPublicKey publicSubkey = getPublicSubKey(encryptionSubkey, bindingSubpacketsCallback, subpackets);
            Key subkey = new Key(new PGPKeyPair(publicSubkey, encryptionSubkey.getPrivateKey()), keyEncryptor);
            subkeys.add(subkey);
            return this;
        }

        /**
         * Add a signing-capable subkey to the OpenPGP key.
         * The binding signature will contain a primary-key back-signature.
         * See {@link PGPKeyPairGenerator#generateSigningSubkey()} for the key type.
         *
         * @return builder
         * @throws PGPException if the key cannot be generated
         */
        public WithPrimaryKey addSigningSubkey()
            throws PGPException
        {
            return addSigningSubkey(new KeyPairGeneratorCallback()
            {
                public PGPKeyPair generateFrom(PGPKeyPairGenerator generator)
                    throws PGPException
                {
                    return generator.generateSigningSubkey();
                }
            });
        }

        /**
         * Add a signing-capable subkey to the OpenPGP key.
         * The binding signature will contain a primary-key back-signature.
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
         * The binding signature will contain a primary-key back-signature.
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
            return addSigningSubkey(new KeyPairGeneratorCallback()
            {
                public PGPKeyPair generateFrom(PGPKeyPairGenerator generator)
                    throws PGPException
                {
                    return generator.generateSigningSubkey();
                }
            }, passphrase);
        }

        /**
         * Add a signing-capable subkey to the OpenPGP key.
         * The signing-key type can be specified by overriding the {@link KeyPairGeneratorCallback}.
         * The binding signature will contain a primary-key back-signature.
         * IMPORTANT: The custom subkey passphrase will only be used, if in the final step the key is retrieved
         * using {@link #build()}.
         * If instead {@link #build(char[])} is used, the key-specific passphrase is overwritten with the argument
         * passed into {@link #build(char[])}.
         *
         * @param keyGenCallback callback to specify the signing-key type
         * @param passphrase     nullable passphrase
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
         * The binding signature will contain a primary-key back-signature.
         * The contents of the binding signature(s) can be modified by overriding the respective
         * {@link SignatureSubpacketsFunction} instances.
         * IMPORTANT: The custom subkey passphrase will only be used, if in the final step the key is retrieved
         * using {@link #build()}.
         * If instead {@link #build(char[])} is used, the key-specific passphrase is overwritten with the argument
         * passed into {@link #build(char[])}.
         *
         * @param keyGenCallback           callback to specify the signing-key type
         * @param bindingSignatureCallback callback to modify the contents of the signing subkey binding signature
         * @param backSignatureCallback    callback to modify the contents of the embedded primary key binding signature
         * @param passphrase               nullable passphrase
         * @return builder
         * @throws PGPException if the key cannot be generated
         */
        public WithPrimaryKey addSigningSubkey(KeyPairGeneratorCallback keyGenCallback,
                                               SignatureSubpacketsFunction bindingSignatureCallback,
                                               SignatureSubpacketsFunction backSignatureCallback,
                                               char[] passphrase)
            throws PGPException
        {
            PGPKeyPair subkey = keyGenCallback.generateFrom(configuration.kpGenProvider.get(PublicKeyPacket.VERSION_6, configuration.keyCreationTime));
            subkey = subkey.asSubkey(configuration.keyFingerprintCalculator);
            PBESecretKeyEncryptor keyEncryptor = configuration.keyEncryptorBuilderProvider.build(passphrase, subkey.getPublicKey().getPublicKeyPacket());
            return addSigningSubkey(subkey, bindingSignatureCallback, backSignatureCallback, keyEncryptor);
        }

        /**
         * Add a signing-capable subkey to the OpenPGP key.
         * The signing-key type can be specified by overriding the {@link KeyPairGeneratorCallback}.
         * The binding signature will contain a primary-key back-signature.
         * The contents of the binding signature(s) can be modified by overriding the respective
         * {@link SignatureSubpacketsFunction} instances.
         * IMPORTANT: The custom key encryptor will only be used, if in the final step the key is retrieved
         * using {@link #build()}.
         * If instead {@link #build(char[])} is used, the key-specific encryptor is overwritten with an encryptor
         * built from the argument passed into {@link #build(char[])}.
         *
         * @param signingSubkey            signing subkey
         * @param bindingSignatureCallback callback to modify the contents of the signing subkey binding signature
         * @param backSignatureCallback    callback to modify the contents of the embedded primary key binding signature
         * @param keyEncryptor             nullable encryptor to protect the signing subkey
         * @return builder
         * @throws PGPException if the key cannot be generated
         */
        public WithPrimaryKey addSigningSubkey(PGPKeyPair signingSubkey,
                                               SignatureSubpacketsFunction bindingSignatureCallback,
                                               SignatureSubpacketsFunction backSignatureCallback,
                                               PBESecretKeyEncryptor keyEncryptor)
            throws PGPException
        {
            if (!(signingSubkey.getPublicKey().getPublicKeyPacket() instanceof PublicSubkeyPacket))
            {
                throw new IllegalArgumentException("Signing subkey MUST NOT consist of primary key packet.");
            }

            if (!PublicKeyUtils.isSigningAlgorithm(signingSubkey.getPublicKey().getAlgorithm()))
            {
                throw new PGPException("Signing key MUST use signing-capable algorithm.");
            }

            PGPSignatureSubpacketGenerator backSigSubpackets = new PGPSignatureSubpacketGenerator();
            backSigSubpackets.setIssuerFingerprint(true, signingSubkey.getPublicKey());
            backSigSubpackets.setSignatureCreationTime(configuration.keyCreationTime);
            if (backSignatureCallback != null)
            {
                backSigSubpackets = backSignatureCallback.apply(backSigSubpackets);
            }

            PGPSignatureSubpacketGenerator bindingSigSubpackets = new PGPSignatureSubpacketGenerator();
            bindingSigSubpackets.setIssuerFingerprint(true, primaryKey.pair.getPublicKey());
            bindingSigSubpackets.setSignatureCreationTime(configuration.keyCreationTime);

            bindingSigSubpackets = signingSubkeySubpackets.apply(bindingSigSubpackets);

            PGPSignatureGenerator backSigGen = new PGPSignatureGenerator(
                configuration.contentSignerBuilderProvider.get(signingSubkey.getPublicKey()),
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

            PGPPublicKey signingPubKey = getPublicSubKey(signingSubkey, bindingSignatureCallback, bindingSigSubpackets);
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
        public OpenPGPKey build()
            throws PGPException
        {
            PGPSecretKey primarySecretKey = new PGPSecretKey(
                primaryKey.pair.getPrivateKey(),
                primaryKey.pair.getPublicKey(),
                configuration.digestCalculatorProvider.get(HashAlgorithmTags.SHA1),
                true,
                primaryKey.encryptor);
            List<PGPSecretKey> keys = new ArrayList<PGPSecretKey>();
            keys.add(primarySecretKey);

            for (Iterator it = subkeys.iterator(); it.hasNext();)
            {
                Key key = (Key)it.next();
                PGPSecretKey subkey = new PGPSecretKey(
                    key.pair.getPrivateKey(),
                    key.pair.getPublicKey(),
                    configuration.digestCalculatorProvider.get(HashAlgorithmTags.SHA1),
                    false,
                    key.encryptor);
                keys.add(subkey);
            }

            PGPSecretKeyRing secretKeys = new PGPSecretKeyRing(keys);
            return new OpenPGPKey(secretKeys, implementation);
        }

        /**
         * Build the {@link PGPSecretKeyRing OpenPGP key} using a single passphrase used to protect all subkeys.
         * The passphrase will override whichever key protectors were specified in previous builder steps.
         *
         * @param passphrase nullable passphrase
         * @return OpenPGP key
         * @throws PGPException if the key cannot be generated
         */
        public OpenPGPKey build(char[] passphrase)
            throws PGPException
        {
            PBESecretKeyEncryptor primaryKeyEncryptor = configuration.keyEncryptorBuilderProvider
                .build(passphrase, primaryKey.pair.getPublicKey().getPublicKeyPacket());
            sanitizeKeyEncryptor(primaryKeyEncryptor);
            PGPSecretKey primarySecretKey = new PGPSecretKey(
                primaryKey.pair.getPrivateKey(),
                primaryKey.pair.getPublicKey(),
                configuration.digestCalculatorProvider.get(HashAlgorithmTags.SHA1),
                true,
                primaryKeyEncryptor);
            List<PGPSecretKey> keys = new ArrayList<PGPSecretKey>();
            keys.add(primarySecretKey);

            for (Iterator it = subkeys.iterator(); it.hasNext();)
            {
                Key key = (Key)it.next();
                PBESecretKeyEncryptor subkeyEncryptor = configuration.keyEncryptorBuilderProvider
                    .build(passphrase, key.pair.getPublicKey().getPublicKeyPacket());
                sanitizeKeyEncryptor(subkeyEncryptor);
                PGPSecretKey subkey = new PGPSecretKey(
                    key.pair.getPrivateKey(),
                    key.pair.getPublicKey(),
                    configuration.digestCalculatorProvider.get(HashAlgorithmTags.SHA1),
                    false,
                    subkeyEncryptor);
                keys.add(subkey);
            }

            if (passphrase != null)
            {
                Arrays.fill(passphrase, (char)0);
            }

            PGPSecretKeyRing secretKeys = new PGPSecretKeyRing(keys);
            return new OpenPGPKey(secretKeys, implementation);
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

        private PGPPublicKey getPublicSubKey(PGPKeyPair encryptionSubkey, SignatureSubpacketsFunction bindingSubpacketsCallback, PGPSignatureSubpacketGenerator subpackets)
            throws PGPException
        {
            if (bindingSubpacketsCallback != null)
            {
                subpackets = bindingSubpacketsCallback.apply(subpackets);
            }

            PGPSignatureGenerator bindingSigGen = new PGPSignatureGenerator(
                configuration.contentSignerBuilderProvider.get(primaryKey.pair.getPublicKey()),
                primaryKey.pair.getPublicKey());
            bindingSigGen.init(PGPSignature.SUBKEY_BINDING, primaryKey.pair.getPrivateKey());
            bindingSigGen.setHashedSubpackets(subpackets.generate());

            PGPSignature bindingSig = bindingSigGen.generateCertification(primaryKey.pair.getPublicKey(), encryptionSubkey.getPublicKey());
            return PGPPublicKey.addCertification(encryptionSubkey.getPublicKey(), bindingSig);
        }
    }

    /**
     * Bundle implementation-specific provider classes.
     */
    private static class Configuration
    {
        final Date keyCreationTime;
        final PGPKeyPairGeneratorProvider kpGenProvider;
        final PGPContentSignerBuilderProvider contentSignerBuilderProvider;
        final PGPDigestCalculatorProvider digestCalculatorProvider;
        final PBESecretKeyEncryptorFactory keyEncryptorBuilderProvider;
        final KeyFingerPrintCalculator keyFingerprintCalculator;

        public Configuration(Date keyCreationTime,
                             PGPKeyPairGeneratorProvider keyPairGeneratorProvider,
                              PGPContentSignerBuilderProvider contentSignerBuilderProvider,
                              PGPDigestCalculatorProvider digestCalculatorProvider,
                              PBESecretKeyEncryptorFactory keyEncryptorBuilderProvider,
                              KeyFingerPrintCalculator keyFingerPrintCalculator)
        {
            this.keyCreationTime = new Date((keyCreationTime.getTime() / 1000) * 1000);
            this.kpGenProvider = keyPairGeneratorProvider;
            this.contentSignerBuilderProvider = contentSignerBuilderProvider;
            this.digestCalculatorProvider = digestCalculatorProvider;
            this.keyEncryptorBuilderProvider = keyEncryptorBuilderProvider;
            this.keyFingerprintCalculator = keyFingerPrintCalculator;
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
