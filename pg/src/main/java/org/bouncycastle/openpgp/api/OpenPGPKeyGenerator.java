package org.bouncycastle.openpgp.api;

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
import org.bouncycastle.openpgp.operator.PGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.PGPKeyPairGenerator;
import org.bouncycastle.openpgp.operator.PGPKeyPairGeneratorProvider;
import org.bouncycastle.util.Arrays;

/**
 * High-level generator class for OpenPGP v6 keys.
 */
public class OpenPGPKeyGenerator
    extends AbstractOpenPGPKeySignatureGenerator
{
    // SECONDS
    private static final long SECONDS_PER_MINUTE = 60;
    private static final long SECONDS_PER_HOUR = 60 * SECONDS_PER_MINUTE;
    private static final long SECONDS_PER_DAY = 24 * SECONDS_PER_HOUR;
    private static final long SECONDS_PER_YEAR = 365 * SECONDS_PER_DAY;

    private final int keyVersion;
    private final OpenPGPImplementation implementationProvider;
    private final Configuration configuration; // contains BC or JCA/JCE implementations

    public OpenPGPKeyGenerator(OpenPGPImplementation implementation,
                               boolean aead,
                               Date creationTime)
        throws PGPException
    {
        this(implementation, PublicKeyPacket.VERSION_6, aead, creationTime);
    }

    public OpenPGPKeyGenerator(OpenPGPImplementation implementationProvider,
                               int version,
                               boolean aead,
                               Date creationTime)
        throws PGPException
    {
        this(
            implementationProvider,
            version,
            implementationProvider.pgpKeyPairGeneratorProvider(),
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
     * @param digestCalculatorProvider     digest calculator provider
     * @param keyEncryptionBuilderProvider secret key encryption builder provider (AEAD)
     * @param keyFingerPrintCalculator     calculator for key fingerprints
     * @param creationTime                 key creation time
     */
    public OpenPGPKeyGenerator(
        OpenPGPImplementation implementationProvider,
        int keyVersion,
        PGPKeyPairGeneratorProvider kpGenProvider,
        PGPDigestCalculatorProvider digestCalculatorProvider,
        PBESecretKeyEncryptorFactory keyEncryptionBuilderProvider,
        KeyFingerPrintCalculator keyFingerPrintCalculator,
        Date creationTime)
    {
        if (keyVersion != PublicKeyPacket.VERSION_4 &&
            keyVersion != PublicKeyPacket.LIBREPGP_5 &&
            keyVersion != PublicKeyPacket.VERSION_6)
        {
            throw new IllegalArgumentException("Generating keys of version " + keyVersion + " is not supported.");
        }

        this.implementationProvider = implementationProvider;
        this.keyVersion = keyVersion;
        this.configuration = new Configuration(creationTime, kpGenProvider, digestCalculatorProvider, keyEncryptionBuilderProvider, keyFingerPrintCalculator);
    }

    /**
     * Generate an OpenPGP key consisting of a certify-only primary key,
     * a dedicated signing-subkey and dedicated encryption-subkey.
     * The key will optionally carry the provided user-id.
     * See {@link PGPKeyPairGenerator#generatePrimaryKey()} for the primary key type,
     * {@link PGPKeyPairGenerator#generateSigningSubkey()} for the signing-subkey type and
     * {@link PGPKeyPairGenerator#generateEncryptionSubkey()} for the encryption-subkey key type.
     *
     * @param userId nullable user id
     * @return OpenPGP key
     * @throws PGPException if the key cannot be prepared
     */
    public WithPrimaryKey classicKey(String userId)
        throws PGPException
    {
        WithPrimaryKey builder = withPrimaryKey()
            .addSigningSubkey()
            .addEncryptionSubkey();

        if (userId != null)
        {
            builder.addUserId(userId);
        }

        return builder;
    }

    /**
     * Generate an OpenPGP key consisting of an Ed25519 certify-only primary key,
     * a dedicated Ed25519 sign-only subkey and dedicated X25519 encryption-only subkey.
     * The key will optionally carry the provided user-id.
     *
     * @param userId nullable user id
     * @return OpenPGP key
     * @throws PGPException if the key cannot be generated
     */
    public WithPrimaryKey ed25519x25519Key(String userId)
        throws PGPException
    {
        WithPrimaryKey builder = withPrimaryKey(new KeyPairGeneratorCallback()
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
            });

        if (userId != null)
        {
            builder.addUserId(userId);
        }

        return builder;
    }


    /**
     * Generate an OpenPGP key consisting of an Ed448 certify-only primary key,
     * a dedicated Ed448 sign-only subkey and dedicated X448 encryption-only subkey.
     * The key will optionally carry the provided user-id.
     *
     * @param userId nullable user id
     * @return OpenPGP key
     * @throws PGPException if the key cannot be generated
     */
    public WithPrimaryKey ed448x448Key(String userId)
        throws PGPException
    {
        WithPrimaryKey builder = withPrimaryKey(new KeyPairGeneratorCallback()
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
            });

        if (userId != null)
        {
            builder.addUserId(userId);
        }

        return builder;
    }

    /**
     * Generate a sign-only OpenPGP key.
     * The key consists of a single, user-id-less primary key, which is capable of signing and certifying.
     * See {@link PGPKeyPairGenerator#generatePrimaryKey()} for the key type.
     *
     * @return sign-only (+certify) OpenPGP key
     * @throws PGPException if the key cannot be generated
     */
    public WithPrimaryKey signOnlyKey()
        throws PGPException
    {
        return withPrimaryKey(
            KeyPairGeneratorCallback.Util.primaryKey(),
            SignatureParameters.Callback.Util.modifyHashedSubpackets(new SignatureSubpacketsFunction()
            {
                @Override
                public PGPSignatureSubpacketGenerator apply(PGPSignatureSubpacketGenerator subpackets)
                {
                    subpackets.removePacketsOfType(SignatureSubpacketTags.KEY_FLAGS);
                    subpackets.setKeyFlags(true, KeyFlags.CERTIFY_OTHER | KeyFlags.SIGN_DATA);
                    return subpackets;
                }
            }));
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
        return withPrimaryKey(KeyPairGeneratorCallback.Util.primaryKey());
    }

    /**
     * Generate an OpenPGP key with a certification-capable primary key.
     * The primary key type can be decided using the {@link KeyPairGeneratorCallback}.
     *
     * @param keyGenCallback callback to decide the key type
     * @return builder
     * @throws PGPException if the key cannot be generated
     */
    public WithPrimaryKey withPrimaryKey(
        KeyPairGeneratorCallback keyGenCallback)
        throws PGPException
    {
        return withPrimaryKey(keyGenCallback, null);
    }

    /**
     * Generate an OpenPGP key with a certification-capable primary key.
     * The primary key type can be decided using the {@link KeyPairGeneratorCallback}.
     * The {@link SignatureParameters.Callback} can be used to modify the preferences in the direct-key self signature.
     * If the callback itself is null, the generator will create a default direct-key signature.
     * If the result of {@link SignatureParameters.Callback#apply(SignatureParameters)} is null, no direct-key
     * signature will be generated for the key.
     *
     * @param keyGenCallback              callback to decide the key type
     * @param preferenceSignatureCallback callback to modify the direct-key signature
     * @return builder
     * @throws PGPException if the key cannot be generated
     */
    public WithPrimaryKey withPrimaryKey(
        KeyPairGeneratorCallback keyGenCallback,
        SignatureParameters.Callback preferenceSignatureCallback)
        throws PGPException
    {
        PGPKeyPair primaryKeyPair = keyGenCallback.generateFrom(configuration.kpGenProvider.get(
            keyVersion, configuration.keyCreationTime));

        if (primaryKeyPair.getPublicKey().getPublicKeyPacket() instanceof PublicSubkeyPacket)
        {
            throw new IllegalArgumentException("Primary key MUST NOT consist of subkey packet.");
        }

        if (!PublicKeyUtils.isSigningAlgorithm(primaryKeyPair.getPublicKey().getAlgorithm()))
        {
            throw new PGPException("Primary key MUST use signing-capable algorithm.");
        }

        SignatureParameters parameters = Utils.applySignatureParameters(preferenceSignatureCallback,
            SignatureParameters.directKeySignature(implementationProvider.policy()));

        if (parameters != null)
        {
            PGPSignatureGenerator preferenceSigGen = Utils.getPgpSignatureGenerator(implementationProvider,
                primaryKeyPair.getPublicKey(), primaryKeyPair.getPrivateKey(), parameters, configuration.keyCreationTime,
                new Utils.HashedSubpacketsOperation()
                {
                    @Override
                    public void operate(PGPSignatureSubpacketGenerator hashedSubpackets)
                        throws PGPException
                    {
                        hashedSubpackets = directKeySignatureSubpackets.apply(hashedSubpackets);
                        hashedSubpackets.setKeyFlags(true, KeyFlags.CERTIFY_OTHER);
                        hashedSubpackets.setKeyExpirationTime(false, 5 * SECONDS_PER_YEAR);
                    }
                });

            primaryKeyPair = new PGPKeyPair(
                Utils.injectCertification(primaryKeyPair.getPublicKey(), preferenceSigGen),
                primaryKeyPair.getPrivateKey());
        }

        return new WithPrimaryKey(implementationProvider, configuration, primaryKeyPair);
    }

    /**
     * Intermediate builder class.
     * Constructs an OpenPGP key from a specified primary key.
     */
    public class WithPrimaryKey
    {
        private final OpenPGPImplementation implementation;
        private final Configuration configuration;
        private PGPKeyPair primaryKey;
        private final List<PGPKeyPair> subkeys = new ArrayList<PGPKeyPair>();

        /**
         * Builder.
         *
         * @param implementation cryptographic implementation
         * @param primaryKey     specified primary key
         */
        private WithPrimaryKey(OpenPGPImplementation implementation, Configuration configuration, PGPKeyPair primaryKey)
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
         * @param userId              user-id
         * @param signatureParameters signature parameters
         * @return builder
         * @throws PGPException if the user-id cannot be added
         */
        public WithPrimaryKey addUserId(
            String userId,
            SignatureParameters.Callback signatureParameters)
            throws PGPException
        {
            // care - needs to run with Java 5.
            if (userId == null || userId.trim().length() == 0)
            {
                throw new IllegalArgumentException("User-ID cannot be null or empty.");
            }

            SignatureParameters parameters = Utils.applySignatureParameters(signatureParameters,
                SignatureParameters.certification(implementation.policy()));

            if (parameters != null)
            {
                PGPSignatureGenerator uidSigGen = Utils.getPgpSignatureGenerator(implementation, primaryKey.getPublicKey(),
                    primaryKey.getPrivateKey(), parameters, configuration.keyCreationTime, null);
                primaryKey = new PGPKeyPair(Utils.injectCertification(userId, primaryKey.getPublicKey(), uidSigGen), primaryKey.getPrivateKey());
            }

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
            return addEncryptionSubkey(KeyPairGeneratorCallback.Util.encryptionKey());
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
            return addEncryptionSubkey(keyGenCallback, null);
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
            SignatureParameters.Callback bindingSubpacketsCallback)
            throws PGPException
        {
            PGPKeyPairGenerator generator = configuration.kpGenProvider.get(
                keyVersion, configuration.keyCreationTime);
            PGPKeyPair subkey = generatorCallback.generateFrom(generator);
            subkey = subkey.asSubkey(implementation.keyFingerPrintCalculator());

            return addEncryptionSubkey(subkey, bindingSubpacketsCallback);
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
         * @return builder
         * @throws PGPException if the key cannot be generated
         */
        public WithPrimaryKey addEncryptionSubkey(
            PGPKeyPair encryptionSubkey,
            SignatureParameters.Callback bindingSubpacketsCallback)
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

            encryptionSubkey = updateSubkey(encryptionSubkey, bindingSubpacketsCallback, new Utils.HashedSubpacketsOperation()
            {
                @Override
                public void operate(PGPSignatureSubpacketGenerator hashedSubpackets)
                    throws PGPException
                {
                    hashedSubpackets = encryptionSubkeySubpackets.apply(hashedSubpackets);
                }
            });

            subkeys.add(encryptionSubkey);
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
            return addSigningSubkey(KeyPairGeneratorCallback.Util.signingKey());
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
         * @return builder
         * @throws PGPException if the key cannot be generated
         */
        public WithPrimaryKey addSigningSubkey(KeyPairGeneratorCallback keyGenCallback)
            throws PGPException
        {
            return addSigningSubkey(keyGenCallback, null, null);
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
         * @return builder
         * @throws PGPException if the key cannot be generated
         */
        public WithPrimaryKey addSigningSubkey(KeyPairGeneratorCallback keyGenCallback,
                                               SignatureParameters.Callback bindingSignatureCallback,
                                               SignatureParameters.Callback backSignatureCallback)
            throws PGPException
        {
            PGPKeyPair subkey = keyGenCallback.generateFrom(configuration.kpGenProvider.get(
                keyVersion, configuration.keyCreationTime));
            subkey = subkey.asSubkey(configuration.keyFingerprintCalculator);
            return addSigningSubkey(subkey, bindingSignatureCallback, backSignatureCallback);
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
         * @return builder
         * @throws PGPException if the key cannot be generated
         */
        public WithPrimaryKey addSigningSubkey(PGPKeyPair signingSubkey,
                                               SignatureParameters.Callback bindingSignatureCallback,
                                               SignatureParameters.Callback backSignatureCallback)
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

            SignatureParameters parameters = Utils.applySignatureParameters(backSignatureCallback,
                SignatureParameters.primaryKeyBinding(implementation.policy()));

            // Generate PrimaryKeySignature (Back-Signature)
            final PGPSignature backSig = Utils.getBackSignature(signingSubkey, parameters, primaryKey.getPublicKey(),
                implementation, configuration.keyCreationTime);

            signingSubkey = updateSubkey(signingSubkey, bindingSignatureCallback, new Utils.HashedSubpacketsOperation()
            {
                @Override
                public void operate(PGPSignatureSubpacketGenerator hashedSubpackets)
                    throws PGPException
                {
                    hashedSubpackets = signingSubkeySubpackets.apply(hashedSubpackets);
                    Utils.addEmbeddedSiganture(backSig, hashedSubpackets);
                }
            });

            subkeys.add(signingSubkey);

            return this;
        }


        /**
         * Build the {@link PGPSecretKeyRing OpenPGP key} without protecting the secret keys.
         *
         * @return OpenPGP key
         * @throws PGPException if the key cannot be generated
         */
        public OpenPGPKey build()
            throws PGPException
        {
            return build(null);
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
                .build(passphrase, primaryKey.getPublicKey().getPublicKeyPacket());
            PGPSecretKey primarySecretKey = new PGPSecretKey(
                primaryKey.getPrivateKey(),
                primaryKey.getPublicKey(),
                configuration.digestCalculatorProvider.get(HashAlgorithmTags.SHA1),
                true,
                primaryKeyEncryptor);
            sanitizeKeyEncryptor(primaryKeyEncryptor);
            List<PGPSecretKey> keys = new ArrayList<PGPSecretKey>();
            keys.add(primarySecretKey);

            for (Iterator it = subkeys.iterator(); it.hasNext(); )
            {
                PGPKeyPair key = (PGPKeyPair)it.next();
                PBESecretKeyEncryptor subkeyEncryptor = configuration.keyEncryptorBuilderProvider
                    .build(passphrase, key.getPublicKey().getPublicKeyPacket());
                PGPSecretKey subkey = new PGPSecretKey(
                    key.getPrivateKey(),
                    key.getPublicKey(),
                    configuration.digestCalculatorProvider.get(HashAlgorithmTags.SHA1),
                    false,
                    subkeyEncryptor);
                sanitizeKeyEncryptor(subkeyEncryptor);
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

        private PGPKeyPair updateSubkey(PGPKeyPair subkey, SignatureParameters.Callback bindingSubpacketsCallback,
                                        Utils.HashedSubpacketsOperation operation)
            throws PGPException
        {
            SignatureParameters parameters = Utils.applySignatureParameters(bindingSubpacketsCallback,
                SignatureParameters.subkeyBinding(implementation.policy()).setSignatureCreationTime(configuration.keyCreationTime));

            if (parameters != null)
            {
                PGPSignatureGenerator bindingSigGen = Utils.getPgpSignatureGenerator(implementation, primaryKey.getPublicKey(),
                    primaryKey.getPrivateKey(), parameters, parameters.getSignatureCreationTime(), operation);

                PGPPublicKey publicSubkey = Utils.injectCertification(subkey.getPublicKey(), bindingSigGen, primaryKey.getPublicKey());
                subkey = new PGPKeyPair(publicSubkey, subkey.getPrivateKey());
            }
            return subkey;
        }
    }

    /**
     * Bundle implementation-specific provider classes.
     */
    private static class Configuration
    {
        final Date keyCreationTime;
        final PGPKeyPairGeneratorProvider kpGenProvider;
        final PGPDigestCalculatorProvider digestCalculatorProvider;
        final PBESecretKeyEncryptorFactory keyEncryptorBuilderProvider;
        final KeyFingerPrintCalculator keyFingerprintCalculator;

        public Configuration(Date keyCreationTime,
                             PGPKeyPairGeneratorProvider keyPairGeneratorProvider,
                             PGPDigestCalculatorProvider digestCalculatorProvider,
                             PBESecretKeyEncryptorFactory keyEncryptorBuilderProvider,
                             KeyFingerPrintCalculator keyFingerPrintCalculator)
        {
            this.keyCreationTime = new Date((keyCreationTime.getTime() / 1000) * 1000);
            this.kpGenProvider = keyPairGeneratorProvider;
            this.digestCalculatorProvider = digestCalculatorProvider;
            this.keyEncryptorBuilderProvider = keyEncryptorBuilderProvider;
            this.keyFingerprintCalculator = keyFingerPrintCalculator;
        }
    }
}
