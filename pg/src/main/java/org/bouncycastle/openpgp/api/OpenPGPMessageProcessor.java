package org.bouncycastle.openpgp.api;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.bouncycastle.bcpg.KeyIdentifier;
import org.bouncycastle.openpgp.IntegrityProtectedInputStream;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPPBEEncryptedData;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPSessionKey;
import org.bouncycastle.openpgp.PGPSessionKeyEncryptedData;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.api.exception.KeyPassphraseException;
import org.bouncycastle.openpgp.operator.PBEDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.SessionKeyDataDecryptorFactory;
import org.bouncycastle.util.Arrays;

public class OpenPGPMessageProcessor
{
    private final OpenPGPImplementation implementation;
    private final Configuration configuration;

    /**
     * Create a new {@link OpenPGPMessageProcessor} using the default {@link OpenPGPImplementation}.
     */
    public OpenPGPMessageProcessor()
    {
        this(OpenPGPImplementation.getInstance());
    }

    /**
     * Create a new {@link OpenPGPMessageProcessor} using the given {@link OpenPGPImplementation}.
     *
     * @param implementation openpgp implementation
     */
    public OpenPGPMessageProcessor(OpenPGPImplementation implementation)
    {
        this(implementation, implementation.policy());
    }

    public OpenPGPMessageProcessor(OpenPGPImplementation implementation, OpenPGPPolicy policy)
    {
        this.implementation = implementation;
        this.configuration = new Configuration(policy);
    }

    /**
     * Add an {@link OpenPGPCertificate} for signature verification.
     * If the message contains any signatures, the provided certificate will be considered as a candidate to verify
     * the signature.
     *
     * @param issuerCertificate OpenPGP certificate
     * @return this
     */
    public OpenPGPMessageProcessor addVerificationCertificate(OpenPGPCertificate issuerCertificate)
    {
        configuration.certificatePool.addItem(issuerCertificate);
        return this;
    }

    public OpenPGPMessageProcessor verifyNotAfter(Date date)
    {
        configuration.verifyNotAfter = date;
        return this;
    }

    public OpenPGPMessageProcessor verifyNotBefore(Date date)
    {
        configuration.verifyNotBefore = date;
        return this;
    }

    /**
     * Add an {@link OpenPGPKey} as potential decryption key.
     * If the message is encrypted for an {@link OpenPGPKey}, this key can be tried to decrypt the message.
     * Keys added via this method will also be available for message decryption if the message was encrypted
     * to an anonymous recipient (wildcard key-id / fingerprint).
     *
     * @param key OpenPGP key
     * @return this
     */
    public OpenPGPMessageProcessor addDecryptionKey(OpenPGPKey key)
    {
        configuration.keyPool.addItem(key);
        return this;
    }

    /**
     * Add an {@link OpenPGPKey} as potential decryption key, along with a {@link KeyPassphraseProvider} dedicated
     * to this key.
     * If the message is encrypted for an {@link OpenPGPKey}, this key can be tried to decrypt the message.
     * Keys added via this method will also be available for message decryption if the message was encrypted
     * to an anonymous recipient (wildcard key-id / fingerprint).
     *
     * @param key OpenPGP key
     * @return this
     */
    public OpenPGPMessageProcessor addDecryptionKey(OpenPGPKey key, char[] passphrase)
    {
        configuration.keyPool.addItem(key);
        configuration.keyPassphraseProvider.addPassphrase(key, passphrase);
        return this;
    }

    /**
     * Add a passphrase for secret key decryption.
     * If the corresponding {@link OpenPGPKey} which key this passphrase is for is known in advance,
     * it is highly advised to call {@link #addDecryptionKey(OpenPGPKey, char[])} instead, due to performance reasons.
     *
     * @param passphrase key-passphrase
     * @return this
     */
    public OpenPGPMessageProcessor addDecryptionKeyPassphrase(char[] passphrase)
    {
        configuration.keyPassphraseProvider.addPassphrase(passphrase);
        return this;
    }

    /**
     * Set a provider for dynamically requesting missing passphrases used to unlock encrypted
     * {@link OpenPGPKey OpenPGPKeys}.
     * This provider is called, if a key cannot be unlocked using any passphrase provided via
     * {@link #addDecryptionKey(OpenPGPKey, char[])}.
     *
     * @param keyPassphraseProvider key passphrase provider
     * @return this
     */
    public OpenPGPMessageProcessor setMissingOpenPGPKeyPassphraseProvider(
            KeyPassphraseProvider keyPassphraseProvider)
    {
        this.configuration.keyPassphraseProvider.setMissingPassphraseCallback(keyPassphraseProvider);
        return this;
    }

    /**
     * Set a {@link OpenPGPKeyMaterialProvider.OpenPGPCertificateProvider} to allow dynamic requesting certificates
     * for signature verification.
     * This provider is called if the requested {@link OpenPGPCertificate} has not yet been added explicitly
     * via {@link #addVerificationCertificate(OpenPGPCertificate)}.
     * This allows lazily requesting verification certificates at runtime.
     *
     * @param certificateProvider provider for OpenPGP certificates
     * @return this
     */
    public OpenPGPMessageProcessor setMissingOpenPGPCertificateProvider(
            OpenPGPKeyMaterialProvider.OpenPGPCertificateProvider certificateProvider)
    {
        configuration.certificatePool.setMissingItemCallback(certificateProvider);
        return this;
    }

    /**
     * Set a provider for {@link OpenPGPKey OpenPGPKeys}, which can be used to decrypt encrypted messages.
     * This provider is called if an {@link OpenPGPKey} required to decrypt the message has not yet been
     * explicitly added via {@link #addDecryptionKey(OpenPGPKey)}.
     * This allows lazily requesting decryption keys at runtime.
     *
     * @param keyProvider provider for OpenPGP keys
     * @return this
     */
    public OpenPGPMessageProcessor setMissingOpenPGPKeyProvider(
            OpenPGPKeyMaterialProvider.OpenPGPKeyProvider keyProvider)
    {
        configuration.keyPool.setMissingItemCallback(keyProvider);
        return this;
    }

    /**
     * Set a passphrase to decrypt a symmetrically encrypted OpenPGP message.
     *
     * @param messagePassphrase passphrase for message decryption
     * @return this
     */
    public OpenPGPMessageProcessor addMessagePassphrase(char[] messagePassphrase)
    {
        this.configuration.addMessagePassphrase(messagePassphrase);
        return this;
    }

    /**
     * Set a {@link MissingMessagePassphraseCallback} which will be invoked if the message is encrypted using a passphrase,
     * but no working passphrase was provided.
     *
     * @param callback callback
     * @return this
     */
    public OpenPGPMessageProcessor setMissingMessagePassphraseCallback(
            MissingMessagePassphraseCallback callback)
    {
        this.configuration.missingMessagePassphraseCallback = callback;
        return this;
    }

    /**
     * Set a {@link PGPSessionKey} with which an encrypted OpenPGP message can be decrypted without the need for
     * using a private key or passphrase.
     * Typically, this method can be used, if the {@link PGPSessionKey} of a message is already known (e.g. because
     * the message has already been decrypted before).
     * The benefit of this is, that public-key operations can be costly.
     *
     * @param sessionKey session key
     * @return this
     */
    public OpenPGPMessageProcessor setSessionKey(PGPSessionKey sessionKey)
    {
        configuration.sessionKey = sessionKey;
        return this;
    }

    /**
     * Process an OpenPGP message.
     *
     * @param messageIn input stream of the OpenPGP message
     * @return plaintext input stream
     * @throws IOException
     * @throws PGPException
     */
    public OpenPGPMessageInputStream process(InputStream messageIn)
            throws IOException, PGPException
    {
        // Remove potential ASCII armoring
        InputStream packetInputStream = PGPUtil.getDecoderStream(messageIn);

        PGPObjectFactory objectFactory = implementation.pgpObjectFactory(packetInputStream);
        OpenPGPMessageInputStream in = new OpenPGPMessageInputStream(objectFactory, this);
        in.process();
        return in;
    }

    Date getVerifyNotBefore()
    {
        return configuration.verifyNotBefore;
    }

    Date getVerifyNotAfter()
    {
        return configuration.verifyNotAfter;
    }

    /**
     * Bundle together metadata about the decryption result.
     * That includes the encrypted data packet itself, the passphrase or (sub-)key that was used to decrypt the
     * session-key, the session-key itself and lastly the resulting decrypted packet input stream.
     */
    static class Decrypted
    {
        final InputStream inputStream;
        final PGPSessionKey sessionKey;
        final PGPEncryptedData esk;
        OpenPGPCertificate.OpenPGPComponentKey decryptionKey;
        char[] decryptionPassphrase;

        public Decrypted(PGPEncryptedData encryptedData,
                         PGPSessionKey decryptedSessionKey,
                         InputStream decryptedIn)
        {
            this.esk = encryptedData;
            this.sessionKey = decryptedSessionKey;
            this.inputStream = decryptedIn;
        }
    }

    /**
     * Decrypt an encrypted data packet by trying passphrases and/or decryption keys.
     *
     * @param encDataList encrypted data
     * @return decrypted data
     * @throws PGPException in case of an error
     */
    Decrypted decrypt(PGPEncryptedDataList encDataList)
            throws PGPException
    {
        // Since decryption using session key is the most "deliberate" and "specific", we'll try that first
        if (configuration.sessionKey != null)
        {
            // decrypt with provided session key
            SessionKeyDataDecryptorFactory decryptorFactory =
                    implementation.sessionKeyDataDecryptorFactory(configuration.sessionKey);
            PGPSessionKeyEncryptedData encData = encDataList.extractSessionKeyEncryptedData();
            InputStream decryptedIn = encData.getDataStream(decryptorFactory);
            IntegrityProtectedInputStream verifyingIn = new IntegrityProtectedInputStream(decryptedIn, encData);

            return new Decrypted(encData, configuration.sessionKey, verifyingIn);
        }

        List<PGPPBEEncryptedData> skesks = skesks(encDataList);
        List<PGPPublicKeyEncryptedData> pkesks = pkesks(encDataList);

        PGPException exception = null;

        // If the user explicitly provided a message passphrase, we'll try that next
        if (!skesks.isEmpty() && !configuration.messagePassphrases.isEmpty())
        {
            for (PGPPBEEncryptedData skesk : skesks)
            {
                for (char[] passphrase : configuration.messagePassphrases)
                {
                    try
                    {
                        // Extract message session key with passphrase
                        PBEDataDecryptorFactory passphraseDecryptorFactory =
                                implementation.pbeDataDecryptorFactory(passphrase);
                        PGPSessionKey decryptedSessionKey = skesk.getSessionKey(passphraseDecryptorFactory);

                        // Decrypt the message with the decrypted session key
                        SessionKeyDataDecryptorFactory skDecryptorFactory =
                                implementation.sessionKeyDataDecryptorFactory(decryptedSessionKey);
                        PGPSessionKeyEncryptedData encData = encDataList.extractSessionKeyEncryptedData();
                        InputStream decryptedIn = encData.getDataStream(skDecryptorFactory);
                        IntegrityProtectedInputStream verifyingIn = new IntegrityProtectedInputStream(decryptedIn, encData);

                        Decrypted decrypted = new Decrypted(encData, decryptedSessionKey, verifyingIn);
                        decrypted.decryptionPassphrase = passphrase;

                        return decrypted;
                    }
                    catch (PGPException e)
                    {
                        onException(e);
                        // cache first exception, then continue to try next skesk if present
                        exception = exception != null ? exception : e;
                    }
                }
            }
        }

        // Then we'll try decryption using secret key(s)
        for (PGPPublicKeyEncryptedData pkesk : pkesks)
        {
            KeyIdentifier identifier = pkesk.getKeyIdentifier();
            OpenPGPKey key = configuration.keyPool.provide(identifier);
            if (key == null)
            {
                continue;
            }

            OpenPGPKey.OpenPGPSecretKey decryptionKey = key.getSecretKeys().get(identifier);
            if (decryptionKey == null)
            {
                continue;
            }

            try
            {
                if (!decryptionKey.isEncryptionKey())
                {
                    throw new PGPException("Key is not an encryption key and can therefore not decrypt.");
                }

                char[] keyPassphrase = configuration.keyPassphraseProvider.getKeyPassword(decryptionKey);
                PGPKeyPair unlockedKey = decryptionKey.unlock(keyPassphrase).getKeyPair();
                if (unlockedKey == null)
                {
                    throw new KeyPassphraseException(decryptionKey, new PGPException("Cannot unlock secret key."));
                }

                // Decrypt the message session key using the private key
                PublicKeyDataDecryptorFactory pkDecryptorFactory =
                        implementation.publicKeyDataDecryptorFactory(unlockedKey.getPrivateKey());
                PGPSessionKey decryptedSessionKey = pkesk.getSessionKey(pkDecryptorFactory);

                // Decrypt the message using the decrypted session key
                SessionKeyDataDecryptorFactory skDecryptorFactory =
                        implementation.sessionKeyDataDecryptorFactory(decryptedSessionKey);
                PGPSessionKeyEncryptedData encData = encDataList.extractSessionKeyEncryptedData();
                InputStream decryptedIn = encData.getDataStream(skDecryptorFactory);
                IntegrityProtectedInputStream verifyingIn = new IntegrityProtectedInputStream(decryptedIn, encData);
                Decrypted decrypted = new Decrypted(encData, decryptedSessionKey, verifyingIn);
                decrypted.decryptionKey = decryptionKey;
                return decrypted;
            }
            catch (PGPException e)
            {
                onException(e);
            }
        }

        // And lastly, we'll prompt the user dynamically for a message passphrase
        if (!skesks.isEmpty() && configuration.missingMessagePassphraseCallback != null)
        {
            char[] passphrase;
            while ((passphrase = configuration.missingMessagePassphraseCallback.getMessagePassphrase()) != null)
            {
                for (PGPPBEEncryptedData skesk : skesks)
                {
                    try
                    {
                        // Decrypt the message session key using a passphrase
                        PBEDataDecryptorFactory passphraseDecryptorFactory = implementation.pbeDataDecryptorFactory(passphrase);
                        PGPSessionKey decryptedSessionKey = skesk.getSessionKey(passphraseDecryptorFactory);

                        // Decrypt the data using the decrypted session key
                        SessionKeyDataDecryptorFactory skDecryptorFactory = implementation.sessionKeyDataDecryptorFactory(decryptedSessionKey);
                        PGPSessionKeyEncryptedData encData = encDataList.extractSessionKeyEncryptedData();
                        InputStream decryptedIn = encData.getDataStream(skDecryptorFactory);
                        IntegrityProtectedInputStream verifyingIn = new IntegrityProtectedInputStream(decryptedIn, encData);
                        Decrypted decrypted = new Decrypted(encData, decryptedSessionKey, verifyingIn);
                        decrypted.decryptionPassphrase = passphrase;
                        return decrypted;
                    }
                    catch (PGPException e)
                    {
                        onException(e);
                        // cache first exception, then continue to try next skesk if present
                        exception = exception != null ? exception : e;
                    }
                }
            }

            if (exception != null)
            {
                throw exception;
            }
        }

        throw new PGPException("No working decryption method found.");
    }

    /**
     * Return all symmetric-key-encrypted-session-key (SKESK) packets leading the encrypted data packet.
     *
     * @param encDataList encrypted data list
     * @return list of skesk packets (might be empty)
     */
    private List<PGPPBEEncryptedData> skesks(PGPEncryptedDataList encDataList)
    {
        List<PGPPBEEncryptedData> list = new ArrayList<PGPPBEEncryptedData>();
        for (PGPEncryptedData encData : encDataList)
        {
            if (encData instanceof PGPPBEEncryptedData)
            {
                list.add((PGPPBEEncryptedData) encData);
            }
        }
        return list;
    }

    /**
     * Return all public-key-encrypted-session-key (PKESK) packets leading the encrypted data packet.
     *
     * @param encDataList encrypted data list
     * @return list of pkesk packets (might be empty)
     */
    private List<PGPPublicKeyEncryptedData> pkesks(PGPEncryptedDataList encDataList)
    {
        List<PGPPublicKeyEncryptedData> list = new ArrayList<PGPPublicKeyEncryptedData>();
        for (PGPEncryptedData encData : encDataList)
        {
            if (encData instanceof PGPPublicKeyEncryptedData)
            {
                list.add((PGPPublicKeyEncryptedData) encData);
            }
        }
        return list;
    }

    OpenPGPCertificate provideCertificate(KeyIdentifier identifier)
    {
        return configuration.certificatePool.provide(identifier);
    }

    OpenPGPImplementation getImplementation()
    {
        return implementation;
    }

    /**
     * Method that can be called if a {@link PGPException} is thrown.
     * If the user provided a {@link PGPExceptionCallback} ({@link Configuration#exceptionCallback} is not null),
     * the exception will be passed along to that callback.
     * Otherwise, nothing happens.
     *
     * @param e exception
     */
    void onException(PGPException e)
    {
        if (configuration.exceptionCallback != null)
        {
            configuration.exceptionCallback.onException(e);
        }
    }

    public static class Configuration
    {
        private final OpenPGPPolicy policy;
        private final OpenPGPKeyMaterialPool.OpenPGPCertificatePool certificatePool;
        private final OpenPGPKeyMaterialPool.OpenPGPKeyPool keyPool;
        private final KeyPassphraseProvider.DefaultKeyPassphraseProvider keyPassphraseProvider;
        public final List<char[]> messagePassphrases = new ArrayList<char[]>();
        private MissingMessagePassphraseCallback missingMessagePassphraseCallback;
        private PGPExceptionCallback exceptionCallback = null;
        private PGPSessionKey sessionKey;
        private Date verifyNotAfter = new Date();       // now
        private Date verifyNotBefore = new Date(0L);    // beginning of time

        public Configuration(OpenPGPPolicy policy)
        {
            this.policy = policy;
            this.certificatePool = new OpenPGPKeyMaterialPool.OpenPGPCertificatePool();
            this.keyPool = new OpenPGPKeyMaterialPool.OpenPGPKeyPool();
            this.keyPassphraseProvider = new KeyPassphraseProvider.DefaultKeyPassphraseProvider();
        }

        /**
         * Add a passphrase that will be tried when a symmetric-key-encrypted-session-key packet is found
         * during the decryption process.
         *
         * @param messagePassphrase passphrase to decrypt the message with
         * @return this
         */
        public Configuration addMessagePassphrase(char[] messagePassphrase)
        {
            boolean found = false;
            for (char[] existing : messagePassphrases)
            {
                found |= Arrays.areEqual(existing, messagePassphrase);
            }

            if (!found)
            {
                messagePassphrases.add(messagePassphrase);
            }
            return this;
        }
    }

    /**
     * Callback to handle {@link PGPException PGPExceptions}.
     */
    public interface PGPExceptionCallback
    {
        void onException(PGPException e);
    }
}
