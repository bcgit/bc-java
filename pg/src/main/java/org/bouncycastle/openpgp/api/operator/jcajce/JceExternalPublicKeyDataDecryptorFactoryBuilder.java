package org.bouncycastle.openpgp.api.operator.jcajce;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.Provider;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Date;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X9ECParametersHolder;
import org.bouncycastle.bcpg.AEADEncDataPacket;
import org.bouncycastle.bcpg.ECDHPublicBCPGKey;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyPacket;
import org.bouncycastle.bcpg.SymmetricEncIntegrityPacket;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.jcajce.spec.HKDFParameterSpec;
import org.bouncycastle.jcajce.util.DefaultJcaJceHelper;
import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.jcajce.util.NamedJcaJceHelper;
import org.bouncycastle.jcajce.util.ProviderJcaJceHelper;
import org.bouncycastle.math.ec.ECAlgorithms;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSessionKey;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.api.OpenPGPKey;
import org.bouncycastle.openpgp.api.operator.AbstractExternalPublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.KeyFingerPrintCalculator;
import org.bouncycastle.openpgp.operator.PGPDataDecryptor;
import org.bouncycastle.openpgp.operator.PGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyConverter;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyDataDecryptorFactoryBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JceSessionKeyDataDecryptorFactoryBuilder;
import org.bouncycastle.util.Strings;

/**
 * Builder for a {@link PublicKeyDataDecryptorFactory} whose private key material is held outside
 * the OpenPGP key - typically on a hardware token - as described by
 * <a href="https://datatracker.ietf.org/doc/draft-dkg-openpgp-external-secrets/">OpenPGP External Secret
 * Keys</a> and signalled by {@link org.bouncycastle.bcpg.SecretKeyPacket#USAGE_EXTERNAL}. This is the
 * JCA/JCE analogue of {@link org.bouncycastle.openpgp.api.operator.bc.BcExternalPublicKeyDataDecryptorFactory}.
 * <p>
 * All session-key recovery logic (packet parsing, length checks, the RFC 6637 / RFC 9580 KDF and key
 * unwrap sequencing) is inherited from {@link AbstractExternalPublicKeyDataDecryptorFactory}, with the
 * cryptographic primitives bound to the configured JCA provider; a subclass supplies only the raw
 * private-key operation by implementing {@link #build(OpenPGPKey.OpenPGPSecretKey)} with a
 * {@link PublicKeyCryptoCallback}, which receives the sender's ephemeral key as a JCA
 * {@link PublicKey} built through the configured provider.
 * <p>
 * Note that a secret key handled through this builder need not actually be external: if the supplied key
 * carries usable software key material, the factory built delegates to
 * {@link JcePublicKeyDataDecryptorFactoryBuilder} so the (much cheaper) in-process path is used instead.
 */
public abstract class JceExternalPublicKeyDataDecryptorFactoryBuilder
{
    private final JcePublicKeyDataDecryptorFactoryBuilder softwareDecryptorFactory = new JcePublicKeyDataDecryptorFactoryBuilder();
    private final JcaPGPDigestCalculatorProviderBuilder digestCalculatorProviderBuilder = new JcaPGPDigestCalculatorProviderBuilder();
    private final JceSessionKeyDataDecryptorFactoryBuilder contentDecryptorFactoryBuilder = new JceSessionKeyDataDecryptorFactoryBuilder();

    private JcaJceHelper helper = new DefaultJcaJceHelper();
    private JcaPGPKeyConverter keyConverter = new JcaPGPKeyConverter();
    private JcaKeyFingerprintCalculator fingerprintCalculator = new JcaKeyFingerprintCalculator();

    public JceExternalPublicKeyDataDecryptorFactoryBuilder()
    {
    }

    /**
     * Set the provider object to use for creating cryptographic primitives in the resulting factory the builder produces.
     *
     * @param provider provider object for cryptographic primitives.
     * @return the current builder.
     */
    public JceExternalPublicKeyDataDecryptorFactoryBuilder setProvider(Provider provider)
    {
        softwareDecryptorFactory.setProvider(provider);
        digestCalculatorProviderBuilder.setProvider(provider);
        contentDecryptorFactoryBuilder.setProvider(provider);
        this.helper = new ProviderJcaJceHelper(provider);
        keyConverter.setProvider(provider);

        return this;
    }

    /**
     * Set the provider name to use for creating cryptographic primitives in the resulting factory the builder produces.
     *
     * @param providerName the name of the provider to reference for cryptographic primitives.
     * @return the current builder.
     */
    public JceExternalPublicKeyDataDecryptorFactoryBuilder setProvider(String providerName)
    {
        softwareDecryptorFactory.setProvider(providerName);
        digestCalculatorProviderBuilder.setProvider(providerName);
        contentDecryptorFactoryBuilder.setProvider(providerName);
        this.helper = new NamedJcaJceHelper(providerName);
        keyConverter.setProvider(providerName);

        return this;
    }

    public JceExternalPublicKeyDataDecryptorFactoryBuilder setContentProvider(Provider provider)
    {
        softwareDecryptorFactory.setContentProvider(provider);
        contentDecryptorFactoryBuilder.setProvider(provider);

        return this;
    }

    public JceExternalPublicKeyDataDecryptorFactoryBuilder setContentProvider(String providerName)
    {
        softwareDecryptorFactory.setContentProvider(providerName);
        contentDecryptorFactoryBuilder.setProvider(providerName);

        return this;
    }

    /**
     * Build a decryptor factory for the given secret key, routing the raw private-key operation to
     * wherever the key material is actually held.
     *
     * @param secretKey the (typically external) OpenPGP secret key
     * @return decryptor factory
     * @throws PGPException if the key cannot be unlocked
     */
    public abstract PublicKeyDataDecryptorFactory build(OpenPGPKey.OpenPGPSecretKey secretKey)
        throws PGPException;

    protected PublicKeyDataDecryptorFactory build(final PGPKeyPair keyPair, final PublicKeyCryptoCallback cryptoCallback)
        throws PGPException
    {
        final PGPPrivateKey privKey = keyPair.getPrivateKey();

        if (privKey != null)
        {
            return softwareDecryptorFactory.build(privKey);
        }

        return new JceExternalFactory(keyPair.getPublicKey(), cryptoCallback, fingerprintCalculator,
            digestCalculatorProviderBuilder.build());
    }

    /**
     * The JCA binding of {@link AbstractExternalPublicKeyDataDecryptorFactory}: the inherited
     * session-key recovery flow drives its primitive operations through the builder's configured
     * providers, and the raw private-key operation goes out through the caller's callback with the
     * ephemeral key converted to a JCA {@link PublicKey} on the way.
     */
    private class JceExternalFactory
        extends AbstractExternalPublicKeyDataDecryptorFactory
    {
        private final PublicKeyCryptoCallback cryptoCallback;

        JceExternalFactory(PGPPublicKey pubKey, PublicKeyCryptoCallback cryptoCallback,
            KeyFingerPrintCalculator fingerPrintCalculator, PGPDigestCalculatorProvider digestCalculatorProvider)
        {
            super(pubKey, fingerPrintCalculator, digestCalculatorProvider);
            this.cryptoCallback = cryptoCallback;
        }

        @Override
        protected byte[] decryptRSA(int keyAlgorithm, byte[] sessionKey)
            throws PGPException
        {
            return cryptoCallback.decryptRSA(keyAlgorithm, sessionKey);
        }

        @Override
        protected byte[] decryptElGamal(int keyAlgorithm, byte[][] secKeyData)
            throws PGPException
        {
            return cryptoCallback.decryptElGamal(keyAlgorithm, secKeyData);
        }

        @Override
        protected byte[] agreeECDH(ECDHPublicBCPGKey ecKey, byte[] ephemeralKeyBytes)
            throws PGPException
        {
            return cryptoCallback.decryptECDH(ecKey, toECPublicKey(ecKey, ephemeralKeyBytes));
        }

        @Override
        protected byte[] agreeX25519(byte[] ephemeralKey)
            throws PGPException
        {
            return cryptoCallback.decryptX25519(toXDHPublicKey(EdECObjectIdentifiers.id_X25519, ephemeralKey));
        }

        @Override
        protected byte[] agreeX448(byte[] ephemeralKey)
            throws PGPException
        {
            return cryptoCallback.decryptX448(toXDHPublicKey(EdECObjectIdentifiers.id_X448, ephemeralKey));
        }

        @Override
        protected byte[] generateHKDFBytes(int hashAlgorithm, byte[] ikm, String info, int keyLen)
            throws PGPException
        {
            String algorithmName;
            switch (hashAlgorithm)
            {
            case HashAlgorithmTags.SHA256:
                algorithmName = "HKDF-SHA256";
                break;
            case HashAlgorithmTags.SHA512:
                algorithmName = "HKDF-SHA512";
                break;
            default:
                throw new PGPException("unsupported HKDF hash algorithm: " + hashAlgorithm);
            }

            try
            {
                // derive through the provider's SecretKeyFactory so the configured provider is honoured
                SecretKeyFactory hkdfFact = helper.createSecretKeyFactory(algorithmName);

                return hkdfFact.generateSecret(
                    new HKDFParameterSpec(ikm, null, Strings.toByteArray(info), keyLen)).getEncoded();
            }
            catch (GeneralSecurityException e)
            {
                throw new PGPException("error performing HKDF: " + e.getMessage(), e);
            }
        }

        @Override
        protected byte[] unwrapSessionData(byte[] keyEnc, int symmetricKeyAlgorithm, byte[] key)
            throws PGPException
        {
            try
            {
                Cipher c = createKeyWrapper(symmetricKeyAlgorithm);
                c.init(Cipher.UNWRAP_MODE, new SecretKeySpec(key, PGPUtil.getSymmetricCipherName(symmetricKeyAlgorithm)));

                return c.unwrap(keyEnc, "Session", Cipher.SECRET_KEY).getEncoded();
            }
            catch (GeneralSecurityException e)
            {
                throw new PGPException("error unwrapping session data: " + e.getMessage(), e);
            }
        }

        // OpenPGP v4
        @Override
        public PGPDataDecryptor createDataDecryptor(boolean withIntegrityPacket, int encAlgorithm, byte[] key)
            throws PGPException
        {
            return contentDecryptorFactoryBuilder.build(new PGPSessionKey(encAlgorithm, key))
                .createDataDecryptor(withIntegrityPacket, encAlgorithm, key);
        }

        // OpenPGP v5
        @Override
        public PGPDataDecryptor createDataDecryptor(AEADEncDataPacket aeadEncDataPacket, PGPSessionKey sessionKey)
            throws PGPException
        {
            return contentDecryptorFactoryBuilder.build(sessionKey)
                .createDataDecryptor(aeadEncDataPacket, sessionKey);
        }

        // OpenPGP v6
        @Override
        public PGPDataDecryptor createDataDecryptor(SymmetricEncIntegrityPacket seipd, PGPSessionKey sessionKey)
            throws PGPException
        {
            return contentDecryptorFactoryBuilder.build(sessionKey)
                .createDataDecryptor(seipd, sessionKey);
        }

        private Cipher createKeyWrapper(int symmetricKeyAlgorithm)
            throws PGPException
        {
            try
            {
                switch (symmetricKeyAlgorithm)
                {
                case SymmetricKeyAlgorithmTags.AES_128:
                case SymmetricKeyAlgorithmTags.AES_192:
                case SymmetricKeyAlgorithmTags.AES_256:
                    return helper.createCipher("AESWrap");
                case SymmetricKeyAlgorithmTags.CAMELLIA_128:
                case SymmetricKeyAlgorithmTags.CAMELLIA_192:
                case SymmetricKeyAlgorithmTags.CAMELLIA_256:
                    return helper.createCipher("CamelliaWrap");
                default:
                    throw new PGPException("unknown wrap algorithm: " + symmetricKeyAlgorithm);
                }
            }
            catch (GeneralSecurityException e)
            {
                throw new PGPException("cannot create cipher: " + e.getMessage(), e);
            }
        }

        private PublicKey toXDHPublicKey(ASN1ObjectIdentifier algorithm, byte[] ephemeralKey)
            throws PGPException
        {
            try
            {
                KeyFactory keyFact = helper.createKeyFactory("XDH");

                return keyFact.generatePublic(new X509EncodedKeySpec(new SubjectPublicKeyInfo(
                    new AlgorithmIdentifier(algorithm), ephemeralKey).getEncoded()));
            }
            catch (IOException e)
            {
                throw new PGPException("error converting ephemeral key: " + e.getMessage(), e);
            }
            catch (GeneralSecurityException e)
            {
                throw new PGPException("error converting ephemeral key: " + e.getMessage(), e);
            }
        }

        private PublicKey toECPublicKey(ECDHPublicBCPGKey ecKey, byte[] pEnc)
            throws PGPException
        {
            X9ECParametersHolder x9Params = ECNamedCurveTable.getByOIDLazy(ecKey.getCurveOID());
            if (x9Params == null)
            {
                throw new PGPException("unable to resolve EC curve: " + ecKey.getCurveOID());
            }

            // the point arrives from the message, so it is attacker-supplied: reject anything that is
            // not a valid, non-infinity point of the recipient key's curve before it goes anywhere near
            // the externally-held private scalar (an invalid-curve attack against the token).
            ECPoint publicPoint;
            try
            {
                publicPoint = ECAlgorithms.cleanPoint(x9Params.getCurve(), x9Params.getCurve().decodePoint(pEnc));
            }
            catch (IllegalArgumentException e)
            {
                throw new PGPException("Invalid ephemeral EC point", e);
            }
            if (publicPoint.isInfinity())
            {
                throw new PGPException("Invalid ephemeral EC point: point at infinity");
            }

            // the only conversion BC offers from a raw point to a JCA key runs through a PGPPublicKey -
            // hence the throwaway packet. Only the point is used; the creation date never leaves this
            // method.
            return keyConverter.getPublicKey(new PGPPublicKey(
                new PublicKeyPacket(
                    getPublicKey().getPublicKeyPacket().getVersion(),
                    PublicKeyAlgorithmTags.ECDH,
                    new Date(),
                    new ECDHPublicBCPGKey(
                        ecKey.getCurveOID(),
                        publicPoint,
                        ecKey.getHashAlgorithm(),
                        ecKey.getSymmetricKeyAlgorithm())),
                fingerprintCalculator));
        }
    }

    /**
     * Callback isolating the raw public-key operations performed while recovering an OpenPGP session
     * key. This is the JCA binding of the hooks
     * {@link AbstractExternalPublicKeyDataDecryptorFactory} drives: ephemeral keys arrive as JCA
     * {@link PublicKey} objects built through the configured provider, and no software private key is
     * passed (the key material is held externally). See that class for the split between what the
     * callback does and what the factory does.
     */
    public static abstract class PublicKeyCryptoCallback
    {
        /**
         * Perform RSA decryption of an encrypted session key.
         *
         * @param keyAlgorithm public key algorithm
         * @param pEnc encrypted session key
         * @return decrypted session key
         * @throws PGPException if the message cannot be decrypted
         */
        public abstract byte[] decryptRSA(int keyAlgorithm,
                                          byte[] pEnc)
            throws PGPException;

        /**
         * Perform ElGamal decryption of an encrypted session key.
         *
         * @param keyAlgorithm public key algorithm
         * @param secKeyData encrypted session key data
         * @return decrypted session key
         * @throws PGPException if the message cannot be decrypted
         */
        public abstract byte[] decryptElGamal(int keyAlgorithm,
                                              byte[][] secKeyData)
            throws PGPException;

        /**
         * Perform an ECDH agreement to calculate a shared secret.
         *
         * @param pubKey our ECDH public key
         * @param ephemeralKey the sender's ephemeral public key
         * @return shared secret
         * @throws PGPException if the message cannot be decrypted
         */
        public abstract byte[] decryptECDH(ECDHPublicBCPGKey pubKey,
                                           PublicKey ephemeralKey)
            throws PGPException;

        /**
         * Perform an X25519 agreement to calculate a shared secret.
         *
         * @param ephemeralKey the sender's ephemeral X25519 public key
         * @return shared secret
         * @throws PGPException if the message cannot be decrypted
         */
        public abstract byte[] decryptX25519(PublicKey ephemeralKey)
            throws PGPException;

        /**
         * Perform an X448 agreement to calculate a shared secret.
         *
         * @param ephemeralKey the sender's ephemeral X448 public key
         * @return shared secret
         * @throws PGPException if the message cannot be decrypted
         */
        public abstract byte[] decryptX448(PublicKey ephemeralKey)
            throws PGPException;
    }
}
