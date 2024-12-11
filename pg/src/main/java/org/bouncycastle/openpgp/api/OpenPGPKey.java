package org.bouncycastle.openpgp.api;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.BCPGInputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.bcpg.KeyIdentifier;
import org.bouncycastle.bcpg.PacketFormat;
import org.bouncycastle.bcpg.SecretKeyPacket;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptorBuilderProvider;
import org.bouncycastle.util.io.Streams;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
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
     * Create an {@link OpenPGPKey} instance based on a {@link PGPSecretKeyRing}.
     *
     * @param keyRing secret key ring
     * @param implementation OpenPGP implementation
     */
    public OpenPGPKey(PGPSecretKeyRing keyRing, OpenPGPImplementation implementation)
    {
        super(keyRing, implementation);

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

    public static OpenPGPKey fromAsciiArmor(String armor)
            throws IOException
    {
        return fromAsciiArmor(armor, OpenPGPImplementation.getInstance());
    }

    public static OpenPGPKey fromAsciiArmor(
            String armor,
            OpenPGPImplementation implementation)
            throws IOException
    {
        return fromBytes(
                armor.getBytes(StandardCharsets.UTF_8),
                implementation);
    }

    public static OpenPGPKey fromInputStream(InputStream inputStream)
            throws IOException
    {
        return fromInputStream(inputStream, OpenPGPImplementation.getInstance());
    }

    public static OpenPGPKey fromInputStream(InputStream inputStream, OpenPGPImplementation implementation)
            throws IOException
    {
        return fromBytes(Streams.readAll(inputStream), implementation);
    }

    public static OpenPGPKey fromBytes(
            byte[] bytes)
            throws IOException
    {
        return fromBytes(bytes, OpenPGPImplementation.getInstance());
    }

    public static OpenPGPKey fromBytes(
            byte[] bytes,
            OpenPGPImplementation implementation)
            throws IOException
    {
        ByteArrayInputStream bIn = new ByteArrayInputStream(bytes);
        InputStream decoderStream = PGPUtil.getDecoderStream(bIn);
        BCPGInputStream pIn = BCPGInputStream.wrap(decoderStream);
        PGPObjectFactory objectFactory = implementation.pgpObjectFactory(pIn);

        Object object = objectFactory.nextObject();
        if (!(object instanceof PGPSecretKeyRing))
        {
            throw new IOException("Not a secret key.");
        }

        PGPSecretKeyRing keyRing = (PGPSecretKeyRing) object;
        return new OpenPGPKey(keyRing, implementation);
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

    @Override
    public PGPSecretKeyRing getPGPKeyRing()
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

        for (String slice : fingerprintComments())
        {
            armorBuilder.addComment(slice);
        }

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

        /**
         * Access the {@link PGPPrivateKey} by unlocking the potentially locked secret key using the provided
         * passphrase. Note: If the key is not locked, it is sufficient to pass null as passphrase.
         *
         * @param passphrase passphrase or null
         * @return unlocked private key
         * @throws PGPException if the key cannot be unlocked
         */
        public PGPPrivateKey unlock(char[] passphrase)
                throws PGPException
        {
            PBESecretKeyDecryptor decryptor = null;
            if (passphrase != null)
            {
                decryptor = decryptorBuilderProvider.provide().build(passphrase);
            }
            return getPGPSecretKey().extractPrivateKey(decryptor);
        }

        public boolean isPassphraseCorrect(char[] passphrase)
        {
            try
            {
                PGPPrivateKey privateKey = unlock(passphrase);
                return privateKey != null;
            }
            catch (PGPException e)
            {
                return false;
            }
        }
    }
}
