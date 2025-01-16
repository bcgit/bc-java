package org.bouncycastle.openpgp.api;

import org.bouncycastle.bcpg.sig.PreferredAlgorithms;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.bouncycastle.openpgp.api.exception.InvalidSigningKeyException;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

public class AbstractOpenPGPDocumentSignatureGenerator<T extends AbstractOpenPGPDocumentSignatureGenerator<T>>
{

    protected final OpenPGPImplementation implementation;
    protected final OpenPGPPolicy policy;

    // Below lists all use the same indexing
    protected final List<PGPSignatureGenerator> signatureGenerators = new ArrayList<>();
    protected final List<OpenPGPKey.OpenPGPSecretKey> signingKeys = new ArrayList<>();
    protected final List<SignatureParameters.Callback> signatureCallbacks = new ArrayList<>();
    protected final List<KeyPassphraseProvider> signingKeyPassphraseProviders = new ArrayList<>();

    protected final KeyPassphraseProvider.DefaultKeyPassphraseProvider defaultKeyPassphraseProvider =
            new KeyPassphraseProvider.DefaultKeyPassphraseProvider();

    protected SubkeySelector signingKeySelector = new SubkeySelector()
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

    public AbstractOpenPGPDocumentSignatureGenerator(OpenPGPImplementation implementation, OpenPGPPolicy policy)
    {
        this.implementation = implementation;
        this.policy = policy;
    }

    /**
     * Replace the default signing key selector with a custom implementation.
     * The signing key selector is responsible for selecting one or more signing subkeys from a signing key.
     *
     * @param signingKeySelector selector for signing (sub-)keys
     * @return this
     */
    public T setSigningKeySelector(SubkeySelector signingKeySelector)
    {
        this.signingKeySelector = Objects.requireNonNull(signingKeySelector);
        return (T) this;
    }


    public T addKeyPassphrase(char[] passphrase)
    {
        defaultKeyPassphraseProvider.addPassphrase(passphrase);
        return (T) this;
    }

    public T addSigningKey(
            OpenPGPKey key)
            throws InvalidSigningKeyException
    {
        return addSigningKey(key, defaultKeyPassphraseProvider);
    }

    /**
     * Add an {@link OpenPGPKey} as signing key.
     * If no (sub-)key in the signing key is capable of creating signatures, or if the key is expired or revoked,
     * this method will throw an {@link InvalidSigningKeyException}.
     * Otherwise, all capable signing subkeys will be used to create detached signatures.
     *
     * @param key OpenPGP key
     * @param passphraseProvider provides the passphrase to unlock the signing key
     * @return this
     *
     * @throws InvalidSigningKeyException if the OpenPGP key does not contain a usable signing subkey
     * @throws PGPException if signing fails
     */
    public T addSigningKey(
            OpenPGPKey key,
            KeyPassphraseProvider passphraseProvider)
            throws InvalidSigningKeyException
    {
        List<OpenPGPCertificate.OpenPGPComponentKey> signingSubkeys = signingKeySelector.select(key, policy);
        if (signingSubkeys.isEmpty())
        {
            throw new InvalidSigningKeyException("Key " + key.getPrettyFingerprint() + " cannot sign.");
        }

        for (OpenPGPCertificate.OpenPGPComponentKey subkey : signingSubkeys)
        {
            OpenPGPKey.OpenPGPSecretKey signingKey = key.getSecretKey(subkey);
            addSigningKey(signingKey, passphraseProvider, null);
        }

        return (T) this;
    }

    public T addSigningKey(
            OpenPGPKey.OpenPGPSecretKey signingKey,
            char[] passphrase,
            SignatureParameters.Callback signatureCallback)
            throws InvalidSigningKeyException
    {
        return addSigningKey(
                signingKey,
                defaultKeyPassphraseProvider.addPassphrase(signingKey, passphrase),
                signatureCallback);
    }

    public T addSigningKey(
            OpenPGPKey.OpenPGPSecretKey signingKey,
            KeyPassphraseProvider passphraseProvider,
            SignatureParameters.Callback signatureCallback)
            throws InvalidSigningKeyException
    {
        if (!signingKey.isSigningKey())
        {
            throw new InvalidSigningKeyException("Subkey cannot sign.");
        }

        signingKeys.add(signingKey);
        signingKeyPassphraseProviders.add(passphraseProvider);
        signatureCallbacks.add(signatureCallback);
        return (T) this;
    }

    protected PGPSignatureGenerator initSignatureGenerator(
            OpenPGPKey.OpenPGPSecretKey signingKey,
            KeyPassphraseProvider passphraseProvider,
            SignatureParameters.Callback signatureCallback)
            throws PGPException
    {
        SignatureParameters parameters = SignatureParameters.dataSignature(policy)
                .setSignatureHashAlgorithm(getPreferredHashAlgorithm(signingKey));

        if (signatureCallback != null)
        {
            parameters = signatureCallback.apply(parameters);
        }

        if (parameters == null)
        {
            throw new IllegalStateException("SignatureParameters Callback MUST NOT return null.");
        }

        if (!signingKey.isSigningKey(parameters.getSignatureCreationTime()))
        {
            throw new InvalidSigningKeyException("Provided key " + signingKey.getKeyIdentifier() +
                    " is not capable of creating data signatures.");
        }

        PGPSignatureGenerator sigGen = new PGPSignatureGenerator(
                implementation.pgpContentSignerBuilder(
                        signingKey.getPublicKey().getPGPPublicKey().getAlgorithm(),
                        parameters.getSignatureHashAlgorithmId()),
                signingKey.getPGPPublicKey());

        char[] passphrase = passphraseProvider.getKeyPassword(signingKey);
        sigGen.init(parameters.getSignatureType(), signingKey.unlock(passphrase));

        PGPSignatureSubpacketGenerator hashedSubpackets = new PGPSignatureSubpacketGenerator();
        hashedSubpackets.setIssuerFingerprint(true, signingKey.getPGPPublicKey());
        hashedSubpackets = parameters.applyToHashedSubpackets(hashedSubpackets);
        sigGen.setHashedSubpackets(hashedSubpackets.generate());

        PGPSignatureSubpacketGenerator unhashedSubpackets = new PGPSignatureSubpacketGenerator();
        unhashedSubpackets = parameters.applyToUnhashedSubpackets(unhashedSubpackets);
        sigGen.setUnhashedSubpackets(unhashedSubpackets.generate());

        return sigGen;
    }

    private int getPreferredHashAlgorithm(OpenPGPCertificate.OpenPGPComponentKey key)
    {
        PreferredAlgorithms hashPreferences = key.getHashAlgorithmPreferences();
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
    }

    public T setMissingKeyPassphraseCallback(KeyPassphraseProvider callback)
    {
        defaultKeyPassphraseProvider.setMissingPassphraseCallback(callback);
        return (T) this;
    }
}
