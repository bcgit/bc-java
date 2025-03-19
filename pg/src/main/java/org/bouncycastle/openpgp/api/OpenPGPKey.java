package org.bouncycastle.openpgp.api;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.KeyIdentifier;
import org.bouncycastle.bcpg.PacketFormat;
import org.bouncycastle.bcpg.PublicKeyPacket;
import org.bouncycastle.bcpg.S2K;
import org.bouncycastle.bcpg.SecretKeyPacket;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPKeyValidationException;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.api.exception.KeyPassphraseException;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptorBuilderProvider;
import org.bouncycastle.openpgp.operator.PBESecretKeyEncryptor;
import org.bouncycastle.openpgp.operator.PBESecretKeyEncryptorFactory;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * An {@link OpenPGPKey} (TSK - transferable secret key) is the pendant to an {@link OpenPGPCertificate},
 * but containing the secret key material in addition to the public components.
 * It consists of one or multiple {@link OpenPGPSecretKey} objects.
 */
public class OpenPGPKey
        extends OpenPGPCertificate
{
    // This class extends OpenPGPCertificate, but also holds secret key components in a dedicated map.
    private final Map<KeyIdentifier, OpenPGPSecretKey> secretKeys;

    /**
     * Create an {@link OpenPGPKey} instance based on a {@link PGPSecretKeyRing}.
     * The {@link OpenPGPImplementation} will be acquired by invoking {@link OpenPGPImplementation#getInstance()}.
     *
     * @param keyRing secret key ring
     */
    public OpenPGPKey(PGPSecretKeyRing keyRing)
    {
        this(keyRing, OpenPGPImplementation.getInstance());
    }

    /**
     * Create an {@link OpenPGPKey} instance based on a {@link PGPSecretKeyRing},
     * a provided {@link OpenPGPImplementation} and its {@link OpenPGPPolicy}.
     *
     * @param keyRing secret key ring
     * @param implementation OpenPGP implementation
     */
    public OpenPGPKey(PGPSecretKeyRing keyRing, OpenPGPImplementation implementation)
    {
        this(keyRing, implementation, implementation.policy());
    }

    /**
     * Create an {@link OpenPGPKey} instance based on a {@link PGPSecretKeyRing},
     * a provided {@link OpenPGPImplementation} and {@link OpenPGPPolicy}.
     *
     * @param keyRing secret key ring
     * @param implementation OpenPGP implementation
     * @param policy OpenPGP policy
     */
    public OpenPGPKey(PGPSecretKeyRing keyRing, OpenPGPImplementation implementation, OpenPGPPolicy policy)
    {
        super(keyRing, implementation, policy);

        // Process and map secret keys
        this.secretKeys = new HashMap<>();
        for (OpenPGPComponentKey key : getKeys())
        {
            KeyIdentifier identifier = key.getKeyIdentifier();
            PGPSecretKey secretKey = keyRing.getSecretKey(identifier);
            if (secretKey == null)
            {
                continue;
            }

            secretKeys.put(identifier, new OpenPGPSecretKey(key, secretKey, implementation.pbeSecretKeyDecryptorBuilderProvider()));
        }
    }

    @Override
    public boolean isSecretKey()
    {
        return true;
    }

    /**
     * Return the {@link OpenPGPCertificate} of this {@link OpenPGPKey}.
     *
     * @return certificate
     */
    public OpenPGPCertificate toCertificate()
    {
        return new OpenPGPCertificate(getPGPPublicKeyRing(), implementation, policy);
    }

    @Override
    public List<OpenPGPCertificateComponent> getComponents()
    {
        // We go through the list of components returned by OpenPGPCertificate and replace those components
        //  where we have the secret key available

        // contains only public components
        List<OpenPGPCertificateComponent> components = super.getComponents();
        for (int i = components.size() - 1 ; i >= 0; i--)
        {
            OpenPGPCertificateComponent component = components.get(i);
            if (component instanceof OpenPGPComponentKey)
            {
                OpenPGPSecretKey secretKey = getSecretKey((OpenPGPComponentKey) component);
                if (secretKey != null)
                {
                    // swap in secret component
                    components.remove(i);
                    components.add(i, secretKey);
                }
            }
        }
        return components;
    }

    public OpenPGPSecretKey getPrimarySecretKey()
    {
        return getSecretKey(getPrimaryKey());
    }

    /**
     * Return a {@link Map} containing all {@link OpenPGPSecretKey} components (secret subkeys) of the key.
     *
     * @return secret key components
     */
    public Map<KeyIdentifier, OpenPGPSecretKey> getSecretKeys()
    {
        return new HashMap<>(secretKeys);
    }

    /**
     * Return the {@link OpenPGPSecretKey} identified by the passed {@link KeyIdentifier}.
     *
     * @param identifier key identifier
     * @return corresponding secret key or null
     */
    public OpenPGPSecretKey getSecretKey(KeyIdentifier identifier)
    {
        return secretKeys.get(identifier);
    }

    /**
     * Return the {@link OpenPGPSecretKey} that corresponds to the passed {@link OpenPGPComponentKey}.
     *
     * @param key component key
     * @return corresponding secret key or null
     */
    public OpenPGPSecretKey getSecretKey(OpenPGPComponentKey key)
    {
        return getSecretKey(key.getKeyIdentifier());
    }

    void replaceSecretKey(OpenPGPSecretKey secretKey)
    {
        keyRing = PGPSecretKeyRing.insertSecretKey((PGPSecretKeyRing) keyRing, secretKey.rawSecKey);
        secretKeys.put(secretKey.getKeyIdentifier(), secretKey);
    }

    @Override
    public PGPSecretKeyRing getPGPKeyRing()
    {
        return getPGPSecretKeyRing();
    }

    public PGPSecretKeyRing getPGPSecretKeyRing()
    {
        return (PGPSecretKeyRing) super.getPGPKeyRing();
    }

    @Override
    public String toAsciiArmoredString()
            throws IOException
    {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ArmoredOutputStream.Builder armorBuilder = ArmoredOutputStream.builder()
                .clearHeaders();

        armorBuilder.addSplitMultilineComment(getPrettyFingerprint());

        for (OpenPGPUserId userId : getPrimaryKey().getUserIDs())
        {
            armorBuilder.addComment(userId.getUserId());
        }

        ArmoredOutputStream aOut = armorBuilder.build(bOut);
        BCPGOutputStream pOut = new BCPGOutputStream(aOut, PacketFormat.CURRENT);

        getPGPKeyRing().encode(pOut);
        pOut.close();
        aOut.close();
        return bOut.toString();
    }

    public byte[] getEncoded(PacketFormat format)
            throws IOException
    {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        BCPGOutputStream pOut = new BCPGOutputStream(bOut, format);
        getPGPSecretKeyRing().encode(pOut);
        pOut.close();
        return bOut.toByteArray();
    }

    /**
     * Secret key component of a {@link org.bouncycastle.openpgp.api.OpenPGPCertificate.OpenPGPPrimaryKey} or
     * {@link org.bouncycastle.openpgp.api.OpenPGPCertificate.OpenPGPSubkey}.
     */
    public static class OpenPGPSecretKey
            extends OpenPGPComponentKey
    {
        private final PGPSecretKey rawSecKey;
        private final OpenPGPComponentKey pubKey;
        private final PBESecretKeyDecryptorBuilderProvider decryptorBuilderProvider;

        /**
         * Constructor.
         *
         * @param pubKey                   corresponding public key component
         * @param secKey                   secret key
         * @param decryptorBuilderProvider for unlocking private keys
         */
        public OpenPGPSecretKey(OpenPGPComponentKey pubKey,
                                PGPSecretKey secKey,
                                PBESecretKeyDecryptorBuilderProvider decryptorBuilderProvider)
        {
            super(pubKey.getPGPPublicKey(), pubKey.getCertificate());
            this.decryptorBuilderProvider = decryptorBuilderProvider;
            this.rawSecKey = secKey;
            this.pubKey = pubKey;
        }

        @Override
        protected OpenPGPCertificateComponent getPublicComponent()
        {
            // return the public key component to properly map this secret key to its public key component when
            //  the public key component is used as key in a map.
            return pubKey;
        }

        @Override
        protected OpenPGPComponentKey getKeyComponent()
        {
            return this;
        }

        @Override
        public boolean isPrimaryKey()
        {
            return getPublicKey().isPrimaryKey();
        }

        @Override
        public OpenPGPComponentSignature getLatestSelfSignature(Date evaluationTime)
        {
            return getPublicKey().getLatestSelfSignature(evaluationTime);
        }

        public OpenPGPKey getOpenPGPKey()
        {
            return (OpenPGPKey) getCertificate();
        }

        @Override
        public String toDetailString()
        {
            return "Private" + pubKey.toDetailString();
        }

        /**
         * Return the underlying {@link PGPSecretKey}.
         *
         * @return secret key
         */
        public PGPSecretKey getPGPSecretKey()
        {
            return rawSecKey;
        }

        /**
         * Return the public {@link OpenPGPComponentKey} corresponding to this {@link OpenPGPSecretKey}.
         *
         * @return public component key
         */
        public OpenPGPComponentKey getPublicKey()
        {
            return pubKey;
        }

        /**
         * If true, the secret key is not available in plain and likely needs to be decrypted by providing
         * a key passphrase.
         */
        public boolean isLocked()
        {
            return getPGPSecretKey().getS2KUsage() != SecretKeyPacket.USAGE_NONE;
        }

        public OpenPGPPrivateKey unlock()
                throws PGPException
        {
            return unlock((char[]) null);
        }

        public OpenPGPPrivateKey unlock(KeyPassphraseProvider passphraseProvider)
                throws PGPException
        {
            if (!isLocked())
            {
                return unlock((char[]) null);
            }
            return unlock(passphraseProvider.getKeyPassword(this));
        }

        /**
         * Access the {@link PGPKeyPair} by unlocking the potentially locked secret key using the provided
         * passphrase. Note: If the key is not locked, it is sufficient to pass null as passphrase.
         *
         * @param passphrase passphrase or null
         * @return keypair containing unlocked private key
         * @throws PGPException if the key cannot be unlocked
         */
        public OpenPGPPrivateKey unlock(char[] passphrase)
                throws PGPException
        {
            sanitizeProtectionMode();
            PBESecretKeyDecryptor decryptor = null;
            try
            {
                if (passphrase != null)
                {
                    decryptor = decryptorBuilderProvider.provide().build(passphrase);
                }

                PGPPrivateKey privateKey = getPGPSecretKey().extractPrivateKey(decryptor);
                if (privateKey == null)
                {
                    return null;
                }

                PGPKeyPair unlockedKey = new PGPKeyPair(getPGPSecretKey().getPublicKey(), privateKey);
                return new OpenPGPPrivateKey(this, unlockedKey);
            }
            catch (PGPException e)
            {
                throw new KeyPassphraseException(this, e);
            }
        }

        private void sanitizeProtectionMode()
                throws PGPException
        {
            if (!isLocked())
            {
                return;
            }

            PGPSecretKey secretKey = getPGPSecretKey();
            S2K s2k = secretKey.getS2K();
            if (s2k == null)
            {
                throw new PGPKeyValidationException("Legacy CFB using MD5 is not allowed.");
            }

            if (s2k.getType() == S2K.ARGON_2 && secretKey.getS2KUsage() != SecretKeyPacket.USAGE_AEAD)
            {
                throw new PGPKeyValidationException("Argon2 without AEAD is not allowed.");
            }

            if (getVersion() == PublicKeyPacket.VERSION_6)
            {
                if (secretKey.getS2KUsage() == SecretKeyPacket.USAGE_CHECKSUM)
                {
                    throw new PGPKeyValidationException("Version 6 keys MUST NOT use malleable CFB.");
                }
                if (s2k.getType() == S2K.SIMPLE)
                {
                    throw new PGPKeyValidationException("Version 6 keys MUST NOT use SIMPLE S2K.");
                }
            }
        }

        public boolean isPassphraseCorrect(char[] passphrase)
        {
            try
            {
                OpenPGPPrivateKey privateKey = unlock(passphrase);
                return privateKey.unlockedKey != null;
            }
            catch (PGPException e)
            {
                return false;
            }
        }
    }

    /**
     * Unlocked {@link OpenPGPSecretKey}.
     */
    public static class OpenPGPPrivateKey
    {
        private final OpenPGPSecretKey secretKey;
        private final PGPKeyPair unlockedKey;

        public OpenPGPPrivateKey(OpenPGPSecretKey secretKey, PGPKeyPair unlockedKey)
        {
            this.secretKey = secretKey;
            this.unlockedKey = unlockedKey;
        }

        public OpenPGPComponentKey getPublicKey()
        {
            return secretKey.getPublicKey();
        }

        /**
         * Return the {@link OpenPGPSecretKey} in its potentially locked form.
         *
         * @return secret key
         */
        public OpenPGPSecretKey getSecretKey()
        {
            return secretKey;
        }

        /**
         * Return the unlocked {@link PGPKeyPair} containing the decrypted {@link PGPPrivateKey}.
         * @return unlocked private key
         */
        public PGPKeyPair getKeyPair()
        {
            return unlockedKey;
        }

        private OpenPGPImplementation getImplementation()
        {
            return getSecretKey().getOpenPGPKey().implementation;
        }

        public OpenPGPSecretKey changePassphrase(char[] newPassphrase)
                throws PGPException
        {
            boolean useAead = !secretKey.isLocked() ||
                    secretKey.getPGPSecretKey().getS2KUsage() == SecretKeyPacket.USAGE_AEAD;

            return changePassphrase(newPassphrase, getImplementation(), useAead);
        }

        public OpenPGPSecretKey changePassphrase(char[] newPassphrase,
                                                 OpenPGPImplementation implementation,
                                                 boolean useAEAD)
                throws PGPException
        {
            return changePassphrase(newPassphrase, implementation.pbeSecretKeyEncryptorFactory(useAEAD));
        }

        public OpenPGPSecretKey changePassphrase(char[] newPassphrase,
                                                 PBESecretKeyEncryptorFactory keyEncryptorFactory)
                throws PGPException
        {
            PBESecretKeyEncryptor keyEncryptor;
            if (newPassphrase == null || newPassphrase.length == 0)
            {
                keyEncryptor = null;
            }
            else
            {
                keyEncryptor = keyEncryptorFactory.build(
                        newPassphrase,
                        getKeyPair().getPublicKey().getPublicKeyPacket());
            }

            return changePassphrase(keyEncryptor);
        }

        public OpenPGPSecretKey changePassphrase(PBESecretKeyEncryptor keyEncryptor)
                throws PGPException
        {
            PGPSecretKey encrypted = new PGPSecretKey(
                getKeyPair().getPrivateKey(),
                getKeyPair().getPublicKey(),
                getImplementation().pgpDigestCalculatorProvider().get(HashAlgorithmTags.SHA1),
                getSecretKey().isPrimaryKey(),
                keyEncryptor);

            OpenPGPSecretKey sk = new OpenPGPSecretKey(
                    getSecretKey().getPublicKey(),
                    encrypted,
                    getImplementation().pbeSecretKeyDecryptorBuilderProvider());
            sk.sanitizeProtectionMode();
            return sk;
        }

        public OpenPGPSecretKey removePassphrase()
                throws PGPException
        {
            return changePassphrase((PBESecretKeyEncryptor) null);
        }
    }
}
