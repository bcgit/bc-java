package org.bouncycastle.openpgp.api;

import org.bouncycastle.bcpg.AEADAlgorithmTags;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.CompressionAlgorithmTags;
import org.bouncycastle.bcpg.KeyIdentifier;
import org.bouncycastle.bcpg.S2K;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.bcpg.sig.PreferredAEADCiphersuites;
import org.bouncycastle.bcpg.sig.PreferredAlgorithms;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyRing;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPOnePassSignature;
import org.bouncycastle.openpgp.PGPPadding;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.bouncycastle.openpgp.api.exception.InvalidEncryptionKeyException;
import org.bouncycastle.openpgp.api.exception.InvalidSigningKeyException;
import org.bouncycastle.openpgp.operator.PBEKeyEncryptionMethodGenerator;
import org.bouncycastle.openpgp.operator.PGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.PublicKeyKeyEncryptionMethodGenerator;

import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.Objects;
import java.util.Stack;
import java.util.stream.Collectors;

public class OpenPGPMessageGenerator
{
    public static final int BUFFER_SIZE = 1024;

    private final OpenPGPImplementation implementation;
    private final Configuration config;

    // Literal Data metadata
    private Date fileModificationDate = null;
    private String filename = null;
    private char format = PGPLiteralData.BINARY;
    private PGPEncryptedDataGenerator.SessionKeyExtractionCallback sessionKeyExtractionCallback;

    public OpenPGPMessageGenerator()
    {
        this(OpenPGPImplementation.getInstance());
    }

    public OpenPGPMessageGenerator(OpenPGPImplementation implementation)
    {
        this(implementation, implementation.policy());
    }

    public OpenPGPMessageGenerator(OpenPGPImplementation implementation, OpenPGPPolicy policy)
    {
        this.implementation = Objects.requireNonNull(implementation);
        this.config = new Configuration(policy);
    }

    /**
     * Add a recipients certificate to the set of encryption keys.
     * Subkeys will be selected using the default {@link SubkeySelector}, which can be replaced by calling
     * {@link Configuration#setEncryptionKeySelector(SubkeySelector)}.
     * The recipient will be able to decrypt the message using their corresponding secret key.
     *
     * @param recipientCertificate recipient certificate (public key)
     * @return this
     */
    public OpenPGPMessageGenerator addEncryptionCertificate(OpenPGPCertificate recipientCertificate)
            throws InvalidEncryptionKeyException
    {
        return addEncryptionCertificate(recipientCertificate, config.encryptionKeySelector);
    }

    /**
     * Add a recipients certificate to the set of encryption keys.
     * Subkeys will be selected using the provided {@link SubkeySelector}.
     * The recipient will be able to decrypt the message using their corresponding secret key.
     *
     * @param recipientCertificate recipient certificate (public key)
     * @param subkeySelector selector for encryption subkeys
     * @return this
     * @throws InvalidEncryptionKeyException if the certificate is not capable of encryption
     */
    public OpenPGPMessageGenerator addEncryptionCertificate(OpenPGPCertificate recipientCertificate,
                                                            SubkeySelector subkeySelector)
            throws InvalidEncryptionKeyException
    {
        List<OpenPGPCertificate.OpenPGPComponentKey> encryptionKeys =
                subkeySelector.select(recipientCertificate, config.policy);
        if (encryptionKeys.isEmpty())
        {
            throw new InvalidEncryptionKeyException("Certificate " + recipientCertificate.getKeyIdentifier() +
                    " does not have valid encryption subkeys.");
        }
        config.encryptionKeys.addAll(encryptionKeys);
        return this;
    }

    /**
     * Add a (sub-)key to the set of recipient encryption keys.
     * The recipient will be able to decrypt the message using their corresponding secret key.
     *
     * @param encryptionKey encryption capable subkey
     * @return this
     * @throws InvalidEncryptionKeyException if the key is not capable of encryption
     */
    public OpenPGPMessageGenerator addEncryptionCertificate(OpenPGPCertificate.OpenPGPComponentKey encryptionKey)
            throws InvalidEncryptionKeyException
    {
        if (!encryptionKey.isEncryptionKey())
        {
            throw new InvalidEncryptionKeyException("Provided subkey " + encryptionKey.getKeyIdentifier() +
                    " is not a valid encryption key.");
        }
        config.encryptionKeys.add(encryptionKey);
        return this;
    }

    /**
     * Add a message passphrase.
     * In addition to optional public key encryption, the message will be decryptable using the given passphrase.
     *
     * @param passphrase passphrase
     * @return this
     */
    public OpenPGPMessageGenerator addEncryptionPassphrase(char[] passphrase)
    {
        config.messagePassphrases.add(passphrase);
        return this;
    }

    /**
     * Sign the message using a secret signing key.
     * The signing subkey(s) will be selected by the default {@link SubkeySelector} which can be replaced by
     * calling {@link Configuration#setSigningKeySelector(SubkeySelector)}.
     *
     * @param signingKey OpenPGP key
     * @return this
     * @throws InvalidSigningKeyException if the key is not capable of signing messages
     */
    public OpenPGPMessageGenerator addSigningKey(OpenPGPKey signingKey)
            throws InvalidSigningKeyException
    {
        return addSigningKey(signingKey, key -> null);
    }

    /**
     * Sign the message using a secret signing key.
     * The signing subkey(s) will be selected by the default {@link SubkeySelector} which can be replaced by
     * calling {@link Configuration#setSigningKeySelector(SubkeySelector)}.
     *
     * @param signingKey OpenPGP key
     * @param signingKeyDecryptorProvider provider for decryptors to unlock the signing (sub-)keys.
     * @return this
     * @throws InvalidSigningKeyException if the key is not capable of signing messages
     */
    public OpenPGPMessageGenerator addSigningKey(
            OpenPGPKey signingKey,
            SecretKeyPassphraseProvider signingKeyDecryptorProvider)
            throws InvalidSigningKeyException
    {
        List<OpenPGPCertificate.OpenPGPComponentKey> publicSigningKeys =
                config.signingKeySelector.select(signingKey, implementation.policy());

        List<OpenPGPKey.OpenPGPSecretKey> signingKeys = new ArrayList<>();
        for (OpenPGPCertificate.OpenPGPComponentKey publicKey : publicSigningKeys)
        {
            OpenPGPKey.OpenPGPSecretKey secretKey = signingKey.getSecretKey(publicKey);
            if (secretKey == null)
            {
                throw new InvalidSigningKeyException("Secret key " + publicKey.getKeyIdentifier() + " is missing from the OpenPGP key.");
            }
            signingKeys.add(secretKey);
        }

        if (signingKeys.isEmpty())
        {
            throw new InvalidSigningKeyException("OpenPGP key " + signingKey.getKeyIdentifier() + " does not have any valid signing subkeys.");
        }

        for (OpenPGPKey.OpenPGPSecretKey subkey : signingKeys)
        {
            config.signingKeys.add(new Signer(subkey, signingKeyDecryptorProvider, null));
        }
        return this;
    }

    /**
     * Sign the message using a signing-capable (sub-)key.
     * If the signing key is protected with a passphrase, the given {@link SecretKeyPassphraseProvider} can be
     * used to unlock the key.
     * The signature can be customized by providing a {@link SignatureParameters.Callback}, which can change
     * the signature type, creation time and signature subpackets.
     *
     * @param signingKey signing-capable subkey
     * @param signingKeyPassphraseProvider provider for key passphrases
     * @param signatureParameterCallback callback to modify the signature
     * @return this
     * @throws InvalidSigningKeyException if the key cannot be used for signing
     */
    public OpenPGPMessageGenerator addSigningKey(
            OpenPGPKey.OpenPGPSecretKey signingKey,
            SecretKeyPassphraseProvider signingKeyPassphraseProvider,
            SignatureParameters.Callback signatureParameterCallback)
            throws InvalidSigningKeyException
    {
        if (!signingKey.isSigningKey())
        {
            throw new InvalidSigningKeyException("Provided key " + signingKey.getKeyIdentifier() + " is not a valid signing key.");
        }

        config.signingKeys.add(new Signer(signingKey, signingKeyPassphraseProvider, signatureParameterCallback));
        return this;
    }

    /**
     * Specify, whether the output OpenPGP message will be ASCII armored or not.
     *
     * @param armored boolean
     * @return this
     */
    public OpenPGPMessageGenerator setArmored(boolean armored)
    {
        this.config.setArmored(armored);
        return this;
    }

    /**
     * Set metadata (filename, modification date, binary format) from a file.
     * @param file file
     * @return this
     */
    public OpenPGPMessageGenerator setFileMetadata(File file)
    {
        this.filename = file.getName();
        this.fileModificationDate = new Date(file.lastModified());
        this.format = PGPLiteralData.BINARY;
        return this;
    }

    /**
     * Set a callback which fires once the session key for message encryption is known.
     * This callback can be used to extract the session key, e.g. to emit it to the user (in case of SOP).
     *
     * @param callback callback
     * @return this
     */
    public OpenPGPMessageGenerator setSessionKeyExtractionCallback(
            PGPEncryptedDataGenerator.SessionKeyExtractionCallback callback)
    {
        this.sessionKeyExtractionCallback = callback;
        return this;
    }

    /**
     * Open an {@link OpenPGPMessageOutputStream} over the given output stream.
     * @param out output stream
     * @return OpenPGP message output stream
     * @throws PGPException if the output stream cannot be created
     */
    public OpenPGPMessageOutputStream open(OutputStream out)
            throws PGPException, IOException
    {
        OpenPGPMessageOutputStream.Builder streamBuilder = OpenPGPMessageOutputStream.builder();

        applyOptionalAsciiArmor(streamBuilder);
        applyOptionalEncryption(streamBuilder, sessionKeyExtractionCallback);
        applySignatures(streamBuilder);
        applyOptionalCompression(streamBuilder);
        applyLiteralDataWrap(streamBuilder);

        return streamBuilder.build(out);
    }

    /**
     * Apply ASCII armor if necessary.
     * The output will only be wrapped in ASCII armor, if {@link #setArmored(boolean)} is set
     * to true (is true by default).
     * The {@link ArmoredOutputStream} will be instantiated using the {@link ArmoredOutputStreamFactory}
     * which can be replaced using {@link Configuration#setArmorStreamFactory(ArmoredOutputStreamFactory)}.
     *
     * @param builder OpenPGP message output stream builder
     */
    private void applyOptionalAsciiArmor(OpenPGPMessageOutputStream.Builder builder)
    {
        if (config.isArmored)
        {
            builder.armor(config.armorStreamFactory);
        }
    }

    /**
     * Optionally apply message encryption.
     * If no recipient certificates and no encryption passphrases were supplied, no encryption
     * will be applied.
     * Otherwise, encryption mode and algorithms will be negotiated and message encryption will be applied.
     *
     * @param builder                      OpenPGP message output stream builder
     * @param sessionKeyExtractionCallback callback to extract the session key (nullable)
     */
    private void applyOptionalEncryption(
            OpenPGPMessageOutputStream.Builder builder,
            PGPEncryptedDataGenerator.SessionKeyExtractionCallback sessionKeyExtractionCallback)
    {
        MessageEncryptionMechanism encryption = config.negotiateEncryption();
        if (!encryption.isEncrypted())
        {
            return; // No encryption
        }

        PGPDataEncryptorBuilder encBuilder = implementation.pgpDataEncryptorBuilder(
                encryption.getSymmetricKeyAlgorithm());

        // Specify container type for the plaintext
        switch (encryption.getMode())
        {
            case SEIPDv1:
                encBuilder.setWithIntegrityPacket(true);
                break;

            case SEIPDv2:
                encBuilder.setWithAEAD(encryption.getAeadAlgorithm(), 6);
                encBuilder.setUseV6AEAD();
                break;

            case LIBREPGP_OED:
                encBuilder.setWithAEAD(encryption.getAeadAlgorithm(), 6);
                encBuilder.setUseV5AEAD();
                break;
        }

        PGPEncryptedDataGenerator encGen = new PGPEncryptedDataGenerator(encBuilder);
        // For sake of interoperability and simplicity, we always use a dedicated session key for message encryption
        //  even if only a single PBE encryption method was added and S2K result could be used as session-key directly.
        encGen.setForceSessionKey(true);
        encGen.setSessionKeyExtractionCallback(sessionKeyExtractionCallback);

        // Setup asymmetric message encryption
        for (OpenPGPCertificate.OpenPGPComponentKey encryptionSubkey : config.encryptionKeys)
        {
            PublicKeyKeyEncryptionMethodGenerator method = implementation.publicKeyKeyEncryptionMethodGenerator(
                    encryptionSubkey.getPGPPublicKey());
            encGen.addMethod(method);
        }

        // Setup symmetric (password-based) message encryption
        for (char[] passphrase : config.messagePassphrases)
        {
            PBEKeyEncryptionMethodGenerator skeskGen;
            switch (encryption.getMode())
            {
                case SEIPDv1:
                case LIBREPGP_OED:
                    // "v4" and LibrePGP use symmetric-key encrypted session key packets version 4 (SKESKv4)
                    skeskGen = implementation.pbeKeyEncryptionMethodGenerator(passphrase);
                    break;

                case SEIPDv2:
                    // v6 uses symmetric-key encrypted session key packets version 6 (SKESKv6) using AEAD
                    skeskGen = implementation.pbeKeyEncryptionMethodGenerator(passphrase, S2K.Argon2Params.memoryConstrainedParameters());
                    break;
                default: continue;
            }

            skeskGen.setSecureRandom(CryptoServicesRegistrar.getSecureRandom()); // Prevent NPE
            encGen.addMethod(skeskGen);
        }

        // Finally apply encryption
        builder.encrypt(o ->
        {
            try
            {
                return encGen.open(o, new byte[BUFFER_SIZE]);
            }
            catch (IOException e)
            {
                throw new PGPException("Could not open encryptor OutputStream", e);
            }
        });

        // Optionally, append a padding packet as the last packet inside the SEIPDv2 packet.
        if (encryption.getMode() == EncryptedDataPacketType.SEIPDv2 && config.isPadded)
        {
            builder.padding(o -> new OpenPGPMessageOutputStream.PaddingPacketAppenderOutputStream(o, PGPPadding::new));
        }
    }

    /**
     * Apply OpenPGP inline-signatures.
     *
     * @param builder OpenPGP message output stream builder
     */
    private void applySignatures(OpenPGPMessageOutputStream.Builder builder)
    {
        builder.sign(o ->
        {
            Stack<PGPSignatureGenerator> signatureGenerators = new Stack<>();
            for (Signer s : config.signingKeys)
            {
                OpenPGPKey.OpenPGPSecretKey signingSubkey = s.signingKey;

                SignatureParameters parameters = SignatureParameters.dataSignature(config.policy)
                        .setSignatureCreationTime(new Date())
                        .setSignatureHashAlgorithm(
                                config.negotiateHashAlgorithm(signingSubkey.getOpenPGPKey(), signingSubkey));
                if (s.signatureParameters != null)
                {
                    parameters = s.signatureParameters.apply(parameters);
                }

                if (parameters == null)
                {
                    throw new IllegalStateException("SignatureParameters callback MUST NOT return null.");
                }

                PGPSignatureGenerator sigGen = new PGPSignatureGenerator(
                        implementation.pgpContentSignerBuilder(
                                signingSubkey.getPGPSecretKey().getPublicKey().getAlgorithm(),
                                parameters.getSignatureHashAlgorithmId()),
                        signingSubkey.getPGPSecretKey().getPublicKey());
                char[] passphrase = signingSubkey.isLocked() ? s.passphraseProvider.providePassphrase(signingSubkey) : null;
                PGPPrivateKey privateKey = signingSubkey.unlock(passphrase);

                sigGen.init(parameters.getSignatureType(), privateKey);
                PGPSignatureSubpacketGenerator hashedSubpackets = new PGPSignatureSubpacketGenerator();
                hashedSubpackets = parameters.applyToHashedSubpackets(hashedSubpackets);
                hashedSubpackets.setIssuerFingerprint(true, signingSubkey.getPGPSecretKey().getPublicKey());
                sigGen.setHashedSubpackets(hashedSubpackets.generate());

                PGPSignatureSubpacketGenerator unhashedSubpackets = new PGPSignatureSubpacketGenerator();
                unhashedSubpackets = parameters.applyToUnhashedSubpackets(unhashedSubpackets);
                sigGen.setUnhashedSubpackets(unhashedSubpackets.generate());

                signatureGenerators.push(sigGen);
            }

            // One-Pass-Signatures
            Iterator<PGPSignatureGenerator> sigGens = signatureGenerators.iterator();
            while (sigGens.hasNext())
            {
                PGPSignatureGenerator gen = sigGens.next();
                PGPOnePassSignature ops = gen.generateOnePassVersion(sigGens.hasNext());
                ops.encode(o);
            }

            return new OpenPGPMessageOutputStream.SignatureGeneratorOutputStream(o, signatureGenerators);
        });
    }

    private void applyOptionalCompression(OpenPGPMessageOutputStream.Builder builder)
    {
        int compressionAlgorithm = config.negotiateCompression();
        if (compressionAlgorithm == CompressionAlgorithmTags.UNCOMPRESSED)
        {
            return; // Uncompressed
        }

        PGPCompressedDataGenerator compGen = new PGPCompressedDataGenerator(compressionAlgorithm);

        builder.compress(o ->
        {
            try
            {
                return compGen.open(o, new byte[BUFFER_SIZE]);
            }
            catch (IOException e)
            {
                throw new PGPException("Could not apply compression", e);
            }
        });
    }

    /**
     * Setup wrapping of the message plaintext in a literal data packet.
     *
     * @param builder OpenPGP message output stream
     */
    private void applyLiteralDataWrap(OpenPGPMessageOutputStream.Builder builder)
    {
        PGPLiteralDataGenerator litGen = new PGPLiteralDataGenerator();
        builder.literalData(o ->
        {
            try
            {
                return litGen.open(o,
                        format,
                        filename != null ? filename : "",
                        fileModificationDate != null ? fileModificationDate : PGPLiteralData.NOW,
                        new byte[BUFFER_SIZE]);
            }
            catch (IOException e)
            {
                throw new PGPException("Could not apply literal data wrapping", e);
            }
        });
    }

    public OpenPGPMessageGenerator setIsPadded(boolean isPadded)
    {
        config.setPadded(isPadded);
        return this;
    }

    public Configuration getConfiguration()
    {
        return config;
    }

    public interface ArmoredOutputStreamFactory
            extends OpenPGPMessageOutputStream.OutputStreamFactory
    {
        ArmoredOutputStream get(OutputStream out);
    }

    public interface CompressionNegotiator
    {
        /**
         * Negotiate a compression algorithm.
         * Returning {@link org.bouncycastle.bcpg.CompressionAlgorithmTags#UNCOMPRESSED} will result in no compression.
         *
         * @param configuration message generator configuration
         * @return negotiated compression algorithm ID
         */
        int negotiateCompression(Configuration configuration, OpenPGPPolicy policy);
    }

    public interface HashAlgorithmNegotiator
    {
        int negotiateHashAlgorithm(OpenPGPKey key, OpenPGPCertificate.OpenPGPComponentKey subkey, OpenPGPPolicy policy);
    }

    public static class Configuration
    {
        private boolean isArmored = true;
        public boolean isPadded = true;
        private final List<OpenPGPCertificate.OpenPGPComponentKey> encryptionKeys = new ArrayList<>();
        private final List<Signer> signingKeys = new ArrayList<>();
        private final List<char[]> messagePassphrases = new ArrayList<>();
        private final OpenPGPPolicy policy;

        public Configuration(OpenPGPPolicy policy)
        {
            this.policy = policy;
        }

        // Factory for creating ASCII armor
        private ArmoredOutputStreamFactory armorStreamFactory =
                outputStream -> ArmoredOutputStream.builder()
                        .clearHeaders()                   // Hide version
                        .enableCRC(false)   // Disable CRC sum
                        .build(outputStream);

        private SubkeySelector encryptionKeySelector = new SubkeySelector()
        {
            @Override
            public List<OpenPGPCertificate.OpenPGPComponentKey> select(OpenPGPCertificate certificate,
                                                                       OpenPGPPolicy policy)
            {
                return certificate.getEncryptionKeys()
                        .stream()
                        .filter(key -> policy.isAcceptablePublicKey(key.getPGPPublicKey()))
                        .collect(Collectors.toList());
            }
        };

        private SubkeySelector signingKeySelector = new SubkeySelector()
        {
            @Override
            public List<OpenPGPCertificate.OpenPGPComponentKey> select(OpenPGPCertificate certificate,
                                                                       OpenPGPPolicy policy)
            {
                return certificate.getSigningKeys()
                        .stream()
                        .filter(key -> policy.isAcceptablePublicKey(key.getPGPPublicKey()))
                        .collect(Collectors.toList());
            }
        };

        // Encryption method negotiator for when only password-based encryption is requested
        private OpenPGPEncryptionNegotiator passwordBasedEncryptionNegotiator = configuration ->
                MessageEncryptionMechanism.aead(SymmetricKeyAlgorithmTags.AES_256, AEADAlgorithmTags.OCB);

        // Encryption method negotiator for when public-key encryption is requested
        private OpenPGPEncryptionNegotiator publicKeyBasedEncryptionNegotiator = configuration ->
        {
            List<OpenPGPCertificate> certificates = encryptionKeys.stream()
                    .map(OpenPGPCertificate.OpenPGPCertificateComponent::getCertificate)
                    .distinct()
                    .collect(Collectors.toList());

            // Decide, if SEIPDv2 (OpenPGP v6-style AEAD) is supported by all recipients.
            if (OpenPGPEncryptionNegotiator.allRecipientsSupportSeipd2(certificates))
            {
                PreferredAEADCiphersuites commonDenominator =
                        OpenPGPEncryptionNegotiator.negotiateAEADCiphersuite(certificates, configuration.policy);
                return MessageEncryptionMechanism.aead(commonDenominator.getAlgorithms()[0]);
            }
            else if (OpenPGPEncryptionNegotiator.allRecipientsSupportLibrePGPOED(certificates))
            {
                return MessageEncryptionMechanism.librePgp(
                        OpenPGPEncryptionNegotiator.bestOEDEncryptionModeByWeight(certificates, configuration.policy));
            }
            else
            {
                return MessageEncryptionMechanism.integrityProtected(
                        OpenPGPEncryptionNegotiator.bestSymmetricKeyAlgorithmByWeight(certificates, configuration.policy));
            }
        };

        // Primary encryption method negotiator
        private final OpenPGPEncryptionNegotiator encryptionNegotiator =
                configuration ->
                {
                    // No encryption methods provided -> Unencrypted message
                    if (configuration.encryptionKeys.isEmpty() && configuration.messagePassphrases.isEmpty())
                    {
                        return MessageEncryptionMechanism.unencrypted();
                    }

                    // No public-key encryption requested -> password-based encryption
                    else if (configuration.encryptionKeys.isEmpty())
                    {
                        // delegate negotiation to pbe negotiator
                        return passwordBasedEncryptionNegotiator.negotiateEncryption(configuration);
                    }
                    else
                    {
                        // delegate negotiation to pkbe negotiator
                        return publicKeyBasedEncryptionNegotiator.negotiateEncryption(configuration);
                    }
                };

        // TODO: Implement properly, taking encryption into account (sign-only should not compress)
        private CompressionNegotiator compressionNegotiator =
                (configuration, policy) -> CompressionAlgorithmTags.UNCOMPRESSED;

        private HashAlgorithmNegotiator hashAlgorithmNegotiator =
                (key, subkey, policy) ->
                {
                    // TODO: Take into consideration hash preferences of recipients, not the sender
                    PreferredAlgorithms hashPreferences = subkey.getHashAlgorithmPreferences();
                    if (hashPreferences != null)
                    {
                        int[] pref = Arrays.stream(hashPreferences.getPreferences())
                                .filter(it -> policy.isAcceptableDocumentSignatureHashAlgorithm(it, new Date()))
                                .toArray();
                        if (pref.length != 0)
                        {
                            return pref[0];
                        }
                    }

                    return policy.getDefaultDocumentSignatureHashAlgorithm();
                };

        /**
         * Replace the default {@link OpenPGPEncryptionNegotiator} that gets to decide, which {@link MessageEncryptionMechanism} mode
         * to use if only password-based encryption is used.
         *
         * @param pbeNegotiator custom PBE negotiator.
         * @return this
         */
        public Configuration setPasswordBasedEncryptionNegotiator(OpenPGPEncryptionNegotiator pbeNegotiator)
        {
            this.passwordBasedEncryptionNegotiator = Objects.requireNonNull(pbeNegotiator);
            return this;
        }

        /**
         * Replace the default {@link OpenPGPEncryptionNegotiator} that decides, which {@link MessageEncryptionMechanism}
         * mode to use if public-key encryption is used.
         *
         * @param pkbeNegotiator custom encryption negotiator that gets to decide if PK-based encryption is used
         * @return this
         */
        public Configuration setPublicKeyBasedEncryptionNegotiator(OpenPGPEncryptionNegotiator pkbeNegotiator)
        {
            this.publicKeyBasedEncryptionNegotiator = Objects.requireNonNull(pkbeNegotiator);
            return this;
        }

        /**
         * Replace the default encryption key selector with a custom implementation.
         * The encryption key selector is responsible for selecting one or more encryption subkeys from a
         * recipient certificate.
         *
         * @param encryptionKeySelector selector for encryption (sub-)keys
         * @return this
         */
        public Configuration setEncryptionKeySelector(SubkeySelector encryptionKeySelector)
        {
            this.encryptionKeySelector = Objects.requireNonNull(encryptionKeySelector);
            return this;
        }

        /**
         * Replace the default signing key selector with a custom implementation.
         * The signing key selector is responsible for selecting one or more signing subkeys from a signing key.
         *
         * @param signingKeySelector selector for signing (sub-)keys
         * @return this
         */
        public Configuration setSigningKeySelector(SubkeySelector signingKeySelector)
        {
            this.signingKeySelector = Objects.requireNonNull(signingKeySelector);
            return this;
        }

        /**
         * Replace the default {@link CompressionNegotiator} with a custom implementation.
         * The {@link CompressionNegotiator} is used to negotiate, whether and how to compress the literal data packet.
         *
         * @param compressionNegotiator negotiator
         * @return this
         */
        public Configuration setCompressionNegotiator(CompressionNegotiator compressionNegotiator)
        {
            this.compressionNegotiator = Objects.requireNonNull(compressionNegotiator);
            return this;
        }

        /**
         * Replace the default {@link HashAlgorithmNegotiator} with a custom implementation.
         *
         * @param hashAlgorithmNegotiator custom hash algorithm negotiator
         * @return this
         */
        public Configuration setHashAlgorithmNegotiator(HashAlgorithmNegotiator hashAlgorithmNegotiator)
        {
            this.hashAlgorithmNegotiator = Objects.requireNonNull(hashAlgorithmNegotiator);
            return this;
        }

        /**
         * Replace the {@link ArmoredOutputStreamFactory} with a custom implementation.
         *
         * @param factory factory for {@link ArmoredOutputStream} instances
         * @return this
         */
        public Configuration setArmorStreamFactory(ArmoredOutputStreamFactory factory)
        {
            this.armorStreamFactory = Objects.requireNonNull(factory);
            return this;
        }

        public Configuration setArmored(boolean isArmored)
        {
            this.isArmored = isArmored;
            return this;
        }

        public Configuration setPadded(boolean isPadded)
        {
            this.isPadded = isPadded;
            return this;
        }

        public int negotiateCompression()
        {
            return compressionNegotiator.negotiateCompression(this, policy);
        }

        public int negotiateHashAlgorithm(OpenPGPKey signingKey, OpenPGPKey.OpenPGPSecretKey signingSubkey)
        {
            return hashAlgorithmNegotiator.negotiateHashAlgorithm(signingKey, signingSubkey, policy);
        }

        public MessageEncryptionMechanism negotiateEncryption()
        {
            return encryptionNegotiator.negotiateEncryption(this);
        }
    }

    /**
     * Tuple representing an OpenPGP key used for signing.
     */
    static class Signer
    {
        private final OpenPGPKey.OpenPGPSecretKey signingKey;
        private final SecretKeyPassphraseProvider passphraseProvider;
        private final SignatureParameters.Callback signatureParameters;

        public Signer(OpenPGPKey.OpenPGPSecretKey signingKey,
                      SecretKeyPassphraseProvider passphraseProvider,
                      SignatureParameters.Callback signatureParameters)
        {
            this.signingKey = signingKey;
            this.passphraseProvider = passphraseProvider;
            this.signatureParameters = signatureParameters;
        }
    }

    /**
     * Interface for selecting a subset of keys from a {@link PGPKeyRing}.
     * This is useful e.g. for selecting a signing key from an OpenPGP key, or a for selecting all
     * encryption capable subkeys of a certificate.
     */
    public interface SubkeySelector
    {
        /**
         * Given a {@link PGPKeyRing}, select a subset of the key rings (sub-)keys and return their
         * {@link KeyIdentifier KeyIdentifiers}.
         *
         * @param certificate OpenPGP key or certificate
         * @param policy OpenPGP algorithm policy
         * @return non-null list of identifiers
         */
        List<OpenPGPCertificate.OpenPGPComponentKey> select(OpenPGPCertificate certificate, OpenPGPPolicy policy);
    }

    public interface SecretKeyPassphraseProvider
    {
        char[] providePassphrase(OpenPGPKey.OpenPGPSecretKey key);
    }
}
