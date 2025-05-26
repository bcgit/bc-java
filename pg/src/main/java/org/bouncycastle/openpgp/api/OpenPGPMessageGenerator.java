package org.bouncycastle.openpgp.api;

import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import org.bouncycastle.bcpg.AEADAlgorithmTags;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.CompressionAlgorithmTags;
import org.bouncycastle.bcpg.S2K;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.bcpg.sig.PreferredAEADCiphersuites;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPOnePassSignature;
import org.bouncycastle.openpgp.PGPPadding;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.api.exception.InvalidEncryptionKeyException;
import org.bouncycastle.openpgp.operator.PBEKeyEncryptionMethodGenerator;
import org.bouncycastle.openpgp.operator.PGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.PublicKeyKeyEncryptionMethodGenerator;

/**
 * Generator for OpenPGP messages.
 * This class can generate armored/unarmored, encrypted and/or signed OpenPGP message artifacts.
 * By default, the generator will merely pack plaintext into an armored
 * {@link org.bouncycastle.bcpg.LiteralDataPacket}.
 * If however, the user provides one or more recipient certificates/keys
 * ({@link #addEncryptionCertificate(OpenPGPCertificate)} /
 * {@link #addEncryptionCertificate(OpenPGPCertificate.OpenPGPComponentKey)})
 * or message passphrases {@link #addEncryptionPassphrase(char[])}, the message will be encrypted.
 * The encryption mechanism is automatically decided, based on the provided recipient certificates, aiming to maximize
 * interoperability.
 * If the user provides one or more signing keys by calling {@link #addSigningKey(OpenPGPKey)} or
 * {@link #addSigningKey(OpenPGPKey.OpenPGPSecretKey, KeyPassphraseProvider, SignatureParameters.Callback)},
 * the message will be signed.
 */
public class OpenPGPMessageGenerator
    extends AbstractOpenPGPDocumentSignatureGenerator<OpenPGPMessageGenerator>
{
    public static final int BUFFER_SIZE = 1024;

    private boolean isArmored = true;
    public boolean isAllowPadding = true;
    private final List<OpenPGPCertificate.OpenPGPComponentKey> encryptionKeys = new ArrayList<OpenPGPCertificate.OpenPGPComponentKey>();
    private final List<char[]> messagePassphrases = new ArrayList<char[]>();

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
        super(implementation, policy);
    }

    /**
     * Add a recipients certificate to the set of encryption keys.
     * Subkeys will be selected using the default {@link SubkeySelector}, which can be replaced by calling
     * {@link #setEncryptionKeySelector(SubkeySelector)}.
     * The recipient will be able to decrypt the message using their corresponding secret key.
     *
     * @param recipientCertificate recipient certificate (public key)
     * @return this
     */
    public OpenPGPMessageGenerator addEncryptionCertificate(OpenPGPCertificate recipientCertificate)
        throws InvalidEncryptionKeyException
    {
        return addEncryptionCertificate(recipientCertificate, encryptionKeySelector);
    }

    /**
     * Add a recipients certificate to the set of encryption keys.
     * Subkeys will be selected using the provided {@link SubkeySelector}.
     * The recipient will be able to decrypt the message using their corresponding secret key.
     *
     * @param recipientCertificate recipient certificate (public key)
     * @param subkeySelector       selector for encryption subkeys
     * @return this
     * @throws InvalidEncryptionKeyException if the certificate is not capable of encryption
     */
    public OpenPGPMessageGenerator addEncryptionCertificate(OpenPGPCertificate recipientCertificate,
                                                            SubkeySelector subkeySelector)
        throws InvalidEncryptionKeyException
    {
        List<OpenPGPCertificate.OpenPGPComponentKey> subkeys =
            subkeySelector.select(recipientCertificate, policy);
        if (subkeys.isEmpty())
        {
            throw new InvalidEncryptionKeyException(recipientCertificate);
        }
        this.encryptionKeys.addAll(subkeys);
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
            throw new InvalidEncryptionKeyException(encryptionKey);
        }
        encryptionKeys.add(encryptionKey);
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
        messagePassphrases.add(passphrase);
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
        this.isArmored = armored;
        return this;
    }

    public OpenPGPMessageGenerator setAllowPadding(boolean allowPadding)
    {
        this.isAllowPadding = allowPadding;
        return this;
    }

    /**
     * Set metadata (filename, modification date, binary format) from a file.
     *
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
     *
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
     * which can be replaced using {@link #setArmorStreamFactory(ArmoredOutputStreamFactory)}.
     *
     * @param builder OpenPGP message output stream builder
     */
    private void applyOptionalAsciiArmor(OpenPGPMessageOutputStream.Builder builder)
    {
        if (isArmored)
        {
            builder.armor(armorStreamFactory);
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
        MessageEncryptionMechanism encryption = encryptionNegotiator.negotiateEncryption(this);
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

        final PGPEncryptedDataGenerator encGen = new PGPEncryptedDataGenerator(encBuilder);
        // For sake of interoperability and simplicity, we always use a dedicated session key for message encryption
        //  even if only a single PBE encryption method was added and S2K result could be used as session-key directly.
        encGen.setForceSessionKey(true);
        encGen.setSessionKeyExtractionCallback(sessionKeyExtractionCallback);

        // Setup asymmetric message encryption
        for (OpenPGPCertificate.OpenPGPComponentKey encryptionSubkey : encryptionKeys)
        {
            PublicKeyKeyEncryptionMethodGenerator method = implementation.publicKeyKeyEncryptionMethodGenerator(
                encryptionSubkey.getPGPPublicKey());
            encGen.addMethod(method);
        }

        // Setup symmetric (password-based) message encryption
        for (char[] passphrase : messagePassphrases)
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
                skeskGen = implementation.pbeKeyEncryptionMethodGenerator(
                    passphrase, S2K.Argon2Params.memoryConstrainedParameters());
                break;
            default:
                continue;
            }

            skeskGen.setSecureRandom(CryptoServicesRegistrar.getSecureRandom()); // Prevent NPE
            encGen.addMethod(skeskGen);
        }

        // Finally apply encryption
        builder.encrypt(new OpenPGPMessageOutputStream.OutputStreamFactory()
        {
            @Override
            public OutputStream get(OutputStream o)
                throws PGPException, IOException
            {
                try
                {
                    return encGen.open(o, new byte[BUFFER_SIZE]);
                }
                catch (IOException e)
                {
                    throw new PGPException("Could not open encryptor OutputStream", e);
                }
            }
        });

        // Optionally, append a padding packet as the last packet inside the SEIPDv2 packet.
        if (encryption.getMode() == EncryptedDataPacketType.SEIPDv2 && isAllowPadding)
        {
            builder.padding(new OpenPGPMessageOutputStream.OutputStreamFactory()
            {
                @Override
                public OutputStream get(OutputStream o)
                {
                    return new OpenPGPMessageOutputStream.PaddingPacketAppenderOutputStream(o, new OpenPGPMessageOutputStream.PaddingPacketFactory()
                    {
                        @Override
                        public PGPPadding providePaddingPacket()
                        {
                            return new PGPPadding();
                        }
                    });
                }
            });
        }
    }

    /**
     * Apply OpenPGP inline-signatures.
     *
     * @param builder OpenPGP message output stream builder
     */
    private void applySignatures(OpenPGPMessageOutputStream.Builder builder)
    {
        builder.sign(new OpenPGPMessageOutputStream.OutputStreamFactory()
        {
            @Override
            public OutputStream get(OutputStream o)
                throws PGPException, IOException
            {
                addSignToGenerator();

                // One-Pass-Signatures
                Iterator<PGPSignatureGenerator> sigGens = signatureGenerators.iterator();
                while (sigGens.hasNext())
                {
                    PGPSignatureGenerator gen = sigGens.next();
                    PGPOnePassSignature ops = gen.generateOnePassVersion(sigGens.hasNext());
                    ops.encode(o);
                }

                return new OpenPGPMessageOutputStream.SignatureGeneratorOutputStream(o, signatureGenerators);
            }
        });
    }

    private void applyOptionalCompression(OpenPGPMessageOutputStream.Builder builder)
    {
        int compressionAlgorithm = compressionNegotiator.negotiateCompression(this, policy);
        if (compressionAlgorithm == CompressionAlgorithmTags.UNCOMPRESSED)
        {
            return; // Uncompressed
        }

        final PGPCompressedDataGenerator compGen = new PGPCompressedDataGenerator(compressionAlgorithm);

        builder.compress(new OpenPGPMessageOutputStream.OutputStreamFactory()
        {
            @Override
            public OutputStream get(OutputStream o)
                throws PGPException, IOException
            {
                try
                {
                    return compGen.open(o, new byte[BUFFER_SIZE]);
                }
                catch (IOException e)
                {
                    throw new PGPException("Could not apply compression", e);
                }
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
        final PGPLiteralDataGenerator litGen = new PGPLiteralDataGenerator();
        builder.literalData(new OpenPGPMessageOutputStream.OutputStreamFactory()
        {
            @Override
            public OutputStream get(final OutputStream o)
                throws PGPException, IOException
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
            }
        });
    }

    // Factory for creating ASCII armor
    private ArmoredOutputStreamFactory armorStreamFactory =
        new ArmoredOutputStreamFactory()
        {
            @Override
            public ArmoredOutputStream get(OutputStream outputStream)
            {
                return ArmoredOutputStream.builder()
                    .clearHeaders()                   // Hide version
                    .enableCRC(false)   // Disable CRC sum
                    .build(outputStream);
            }
        };

    private SubkeySelector encryptionKeySelector = new SubkeySelector()
    {
        @Override
        public List<OpenPGPCertificate.OpenPGPComponentKey> select(OpenPGPCertificate certificate,
                                                                   OpenPGPPolicy policy)
        {
            List<OpenPGPCertificate.OpenPGPComponentKey> result = new ArrayList<OpenPGPCertificate.OpenPGPComponentKey>();
            for (Iterator<OpenPGPCertificate.OpenPGPComponentKey> it = certificate.getEncryptionKeys().iterator(); it.hasNext(); )
            {
                OpenPGPCertificate.OpenPGPComponentKey key = it.next();
                if (policy.isAcceptablePublicKey(key.getPGPPublicKey()))
                {
                    result.add(key);
                }
            }
            return result;
        }
    };

    // Encryption method negotiator for when only password-based encryption is requested
    private OpenPGPEncryptionNegotiator passwordBasedEncryptionNegotiator = new OpenPGPEncryptionNegotiator()
    {
        @Override
        public MessageEncryptionMechanism negotiateEncryption(OpenPGPMessageGenerator configuration)
        {
            return MessageEncryptionMechanism.aead(SymmetricKeyAlgorithmTags.AES_256, AEADAlgorithmTags.OCB);
        }
    };

    // Encryption method negotiator for when public-key encryption is requested
    private OpenPGPEncryptionNegotiator publicKeyBasedEncryptionNegotiator = new OpenPGPEncryptionNegotiator()
    {
        @Override
        public MessageEncryptionMechanism negotiateEncryption(OpenPGPMessageGenerator configuration)
        {
//            List<OpenPGPCertificate> certificates = encryptionKeys.stream()
//                .map(OpenPGPCertificate.OpenPGPCertificateComponent::getCertificate)
//                .distinct()
//                .collect(Collectors.toList());

            List<OpenPGPCertificate> certificates = new ArrayList<OpenPGPCertificate>();
            Set<OpenPGPCertificate> uniqueCertificates = new HashSet<OpenPGPCertificate>(); // For distinctness

            for (Iterator<OpenPGPCertificate.OpenPGPComponentKey> it = encryptionKeys.iterator(); it.hasNext(); )
            {
                OpenPGPCertificate cert = it.next().getCertificate();
                if (uniqueCertificates.add(cert))
                { // `Set.add()` returns true if the element was new
                    certificates.add(cert);
                }
            }

            // Decide, if SEIPDv2 (OpenPGP v6-style AEAD) is supported by all recipients.
            if (OpenPGPEncryptionNegotiator.allRecipientsSupportSeipd2(certificates))
            {
                PreferredAEADCiphersuites commonDenominator =
                    OpenPGPEncryptionNegotiator.negotiateAEADCiphersuite(certificates, policy);
                return MessageEncryptionMechanism.aead(commonDenominator.getAlgorithms()[0]);
            }
            else if (OpenPGPEncryptionNegotiator.allRecipientsSupportLibrePGPOED(certificates))
            {
                return MessageEncryptionMechanism.librePgp(
                    OpenPGPEncryptionNegotiator.bestOEDEncryptionModeByWeight(certificates, policy));
            }
            else
            {
                return MessageEncryptionMechanism.integrityProtected(
                    OpenPGPEncryptionNegotiator.bestSymmetricKeyAlgorithmByWeight(
                        certificates, policy));
            }

        }
    };

    // Primary encryption method negotiator
    private final OpenPGPEncryptionNegotiator encryptionNegotiator = new OpenPGPEncryptionNegotiator()
    {
        @Override
        public MessageEncryptionMechanism negotiateEncryption(OpenPGPMessageGenerator configuration)
        {
            // No encryption methods provided -> Unencrypted message
            if (encryptionKeys.isEmpty() && messagePassphrases.isEmpty())
            {
                return MessageEncryptionMechanism.unencrypted();
            }

            // No public-key encryption requested -> password-based encryption
            else if (encryptionKeys.isEmpty())
            {
                // delegate negotiation to pbe negotiator
                return passwordBasedEncryptionNegotiator.negotiateEncryption(configuration);
            }
            else
            {
                // delegate negotiation to pkbe negotiator
                return publicKeyBasedEncryptionNegotiator.negotiateEncryption(configuration);
            }
        }
    };


    // TODO: Implement properly, taking encryption into account (sign-only should not compress)
    private CompressionNegotiator compressionNegotiator = new CompressionNegotiator()
    {
        @Override
        public int negotiateCompression(OpenPGPMessageGenerator configuration, OpenPGPPolicy policy)
        {
            return CompressionAlgorithmTags.UNCOMPRESSED;
        }
    };

    /**
     * Replace the default {@link OpenPGPEncryptionNegotiator} that gets to decide, which
     * {@link MessageEncryptionMechanism} mode to use if only password-based encryption is used.
     *
     * @param pbeNegotiator custom PBE negotiator.
     * @return this
     */
    public OpenPGPMessageGenerator setPasswordBasedEncryptionNegotiator(OpenPGPEncryptionNegotiator pbeNegotiator)
    {
        if (pbeNegotiator == null)
        {
            throw new NullPointerException();
        }
        this.passwordBasedEncryptionNegotiator = pbeNegotiator;
        return this;
    }

    /**
     * Replace the default {@link OpenPGPEncryptionNegotiator} that decides, which
     * {@link MessageEncryptionMechanism} mode to use if public-key encryption is used.
     *
     * @param pkbeNegotiator custom encryption negotiator that gets to decide if PK-based encryption is used
     * @return this
     */
    public OpenPGPMessageGenerator setPublicKeyBasedEncryptionNegotiator(OpenPGPEncryptionNegotiator pkbeNegotiator)
    {
        if (pkbeNegotiator == null)
        {
            throw new NullPointerException();
        }
        this.publicKeyBasedEncryptionNegotiator = pkbeNegotiator;
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
    public OpenPGPMessageGenerator setEncryptionKeySelector(SubkeySelector encryptionKeySelector)
    {
        if (encryptionKeySelector == null)
        {
            throw new NullPointerException();
        }
        this.encryptionKeySelector = encryptionKeySelector;
        return this;
    }


    /**
     * Replace the default {@link CompressionNegotiator} with a custom implementation.
     * The {@link CompressionNegotiator} is used to negotiate, whether and how to compress the literal data packet.
     *
     * @param compressionNegotiator negotiator
     * @return this
     */
    public OpenPGPMessageGenerator setCompressionNegotiator(CompressionNegotiator compressionNegotiator)
    {
        if (compressionNegotiator == null)
        {
            throw new NullPointerException();
        }
        this.compressionNegotiator = compressionNegotiator;
        return this;
    }

    /**
     * Replace the {@link ArmoredOutputStreamFactory} with a custom implementation.
     *
     * @param factory factory for {@link ArmoredOutputStream} instances
     * @return this
     */
    public OpenPGPMessageGenerator setArmorStreamFactory(ArmoredOutputStreamFactory factory)
    {
        if (factory == null)
        {
            throw new NullPointerException();
        }
        this.armorStreamFactory = factory;
        return this;
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
         * @param messageGenerator message generator
         * @return negotiated compression algorithm ID
         */
        int negotiateCompression(OpenPGPMessageGenerator messageGenerator, OpenPGPPolicy policy);
    }

}
