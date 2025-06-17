package org.bouncycastle.openpgp.api;

import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;
import java.util.List;

import org.bouncycastle.bcpg.sig.PreferredAlgorithms;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.api.exception.InvalidSigningKeyException;
import org.bouncycastle.openpgp.api.exception.KeyPassphraseException;

public class AbstractOpenPGPDocumentSignatureGenerator<T extends AbstractOpenPGPDocumentSignatureGenerator<T>>
{

    protected final OpenPGPImplementation implementation;
    protected final OpenPGPPolicy policy;

    // Below lists all use the same indexing
    protected final List<PGPSignatureGenerator> signatureGenerators = new ArrayList<PGPSignatureGenerator>();
    protected final List<OpenPGPKey.OpenPGPSecretKey> signingKeys = new ArrayList<OpenPGPKey.OpenPGPSecretKey>();
    protected final List<SignatureParameters.Callback> signatureCallbacks = new ArrayList<SignatureParameters.Callback>();
    protected final List<KeyPassphraseProvider> signingKeyPassphraseProviders = new ArrayList<KeyPassphraseProvider>();

    protected final KeyPassphraseProvider.DefaultKeyPassphraseProvider defaultKeyPassphraseProvider =
        new KeyPassphraseProvider.DefaultKeyPassphraseProvider();

    protected SubkeySelector signingKeySelector = new SubkeySelector()
    {
        @Override
        public List<OpenPGPCertificate.OpenPGPComponentKey> select(OpenPGPCertificate certificate,
                                                                   final OpenPGPPolicy policy)
        {
            List<OpenPGPCertificate.OpenPGPComponentKey> result = new ArrayList<OpenPGPCertificate.OpenPGPComponentKey>();
            for (Iterator<OpenPGPCertificate.OpenPGPComponentKey> it = certificate.getSigningKeys().iterator(); it.hasNext(); )
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
        if (signingKeySelector == null)
        {
             throw new NullPointerException();
        }
        this.signingKeySelector = signingKeySelector;
        return (T)this;
    }

    /**
     * Add a passphrase for unlocking signing keys to the set of available passphrases.
     *
     * @param passphrase passphrase
     * @return this
     */
    public T addKeyPassphrase(char[] passphrase)
    {
        defaultKeyPassphraseProvider.addPassphrase(passphrase);
        return (T)this;
    }

    /**
     * Add an {@link OpenPGPKey} for message signing.
     * The {@link #signingKeySelector} is responsible for selecting one or more subkeys of the key to sign with.
     * If no (sub-)key in the signing key is capable of creating signatures, or if the key is expired or revoked,
     * this method will throw an {@link InvalidSigningKeyException}.
     *
     * @param key OpenPGP key
     * @return this
     * @throws InvalidSigningKeyException if the key is not capable of signing
     */
    public T addSigningKey(
        OpenPGPKey key)
        throws InvalidSigningKeyException
    {
        return addSigningKey(key, defaultKeyPassphraseProvider);
    }

    /**
     * Add an {@link OpenPGPKey} for message signing, using the provided {@link KeyPassphraseProvider} to
     * unlock protected subkeys.
     * The {@link #signingKeySelector} is responsible for selecting one or more subkeys of the key to sign with.
     * If no (sub-)key in the signing key is capable of creating signatures, or if the key is expired or revoked,
     * this method will throw an {@link InvalidSigningKeyException}.
     *
     * @param key                OpenPGP key
     * @param passphraseProvider provides the passphrase to unlock the signing key
     * @return this
     * @throws InvalidSigningKeyException if the OpenPGP key does not contain a usable signing subkey
     */
    public T addSigningKey(
        OpenPGPKey key,
        KeyPassphraseProvider passphraseProvider)
        throws InvalidSigningKeyException
    {
        return addSigningKey(key, passphraseProvider, null);
    }

    /**
     * Add an {@link OpenPGPKey} for message signing, using the {@link SignatureParameters.Callback} to
     * allow modification of the signature contents.
     * The {@link #signingKeySelector} is responsible for selecting one or more subkeys of the key to sign with.
     * If no (sub-)key in the signing key is capable of creating signatures, or if the key is expired or revoked,
     * this method will throw an {@link InvalidSigningKeyException}.
     *
     * @param key               OpenPGP key
     * @param signatureCallback optional callback to modify the signature contents with
     * @return this
     * @throws InvalidSigningKeyException if the OpenPGP key does not contain a usable signing subkey
     */
    public T addSigningKey(
        OpenPGPKey key,
        SignatureParameters.Callback signatureCallback)
        throws InvalidSigningKeyException
    {
        return addSigningKey(key, defaultKeyPassphraseProvider, signatureCallback);
    }

    /**
     * Add an {@link OpenPGPKey} for message signing, using the given {@link KeyPassphraseProvider}
     * for unlocking protected subkeys and using the {@link SignatureParameters.Callback} to allow
     * modification of the signature contents.
     * The {@link #signingKeySelector} is responsible for selecting one or more subkeys of the key to sign with.
     * If no (sub-)key in the signing key is capable of creating signatures, or if the key is expired or revoked,
     * this method will throw an {@link InvalidSigningKeyException}.
     *
     * @param key                OpenPGP key
     * @param passphraseProvider key passphrase provider
     * @param signatureCallback  optional callback to modify the signature contents with
     * @return this
     * @throws InvalidSigningKeyException if the OpenPGP key does not contain a usable signing subkey
     */
    public T addSigningKey(
        OpenPGPKey key,
        KeyPassphraseProvider passphraseProvider,
        SignatureParameters.Callback signatureCallback)
        throws InvalidSigningKeyException
    {
        List<OpenPGPCertificate.OpenPGPComponentKey> signingSubkeys = signingKeySelector.select(key, policy);
        if (signingSubkeys.isEmpty())
        {
            throw new InvalidSigningKeyException(key);
        }

        for (Iterator it = signingSubkeys.iterator(); it.hasNext(); )
        {
            OpenPGPKey.OpenPGPSecretKey signingKey = key.getSecretKey((OpenPGPCertificate.OpenPGPComponentKey)it.next());
            addSigningKey(signingKey, passphraseProvider, signatureCallback);
        }

        return (T)this;
    }

    /**
     * Add the given signing (sub-)key for message signing, using the optional passphrase to unlock the
     * key in case its locked, and using the given {@link SignatureParameters.Callback} to allow
     * modification of the signature contents.
     *
     * @param signingKey        signing (sub-)key
     * @param passphrase        optional subkey passphrase
     * @param signatureCallback optional callback to modify the signature contents
     * @return this
     * @throws InvalidSigningKeyException if the subkey is not signing-capable
     */
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

    /**
     * Add the given signing (sub-)key for message signing, using the passphrase provider to unlock the
     * key in case its locked, and using the given {@link SignatureParameters.Callback} to allow
     * modification of the signature contents.
     *
     * @param signingKey         signing (sub-)key
     * @param passphraseProvider passphrase provider for unlocking the subkey
     * @param signatureCallback  optional callback to modify the signature contents
     * @return this
     * @throws InvalidSigningKeyException if the subkey is not signing-capable
     */
    public T addSigningKey(
        OpenPGPKey.OpenPGPSecretKey signingKey,
        KeyPassphraseProvider passphraseProvider,
        SignatureParameters.Callback signatureCallback)
        throws InvalidSigningKeyException
    {
        if (!signingKey.isSigningKey())
        {
            throw new InvalidSigningKeyException(signingKey);
        }

        signingKeys.add(signingKey);
        signingKeyPassphraseProviders.add(passphraseProvider);
        signatureCallbacks.add(signatureCallback);
        return (T)this;
    }

    protected PGPSignatureGenerator initSignatureGenerator(
        OpenPGPKey.OpenPGPSecretKey signingKey,
        KeyPassphraseProvider passphraseProvider,
        SignatureParameters.Callback signatureCallback)
        throws PGPException
    {
        SignatureParameters parameters = Utils.applySignatureParameters(signatureCallback,
            SignatureParameters.dataSignature(policy).setSignatureHashAlgorithm(getPreferredHashAlgorithm(signingKey)));

        if (parameters == null)
        {
            throw new IllegalStateException("SignatureParameters Callback MUST NOT return null.");
        }

        if (!signingKey.isSigningKey(parameters.getSignatureCreationTime()))
        {
            throw new InvalidSigningKeyException(signingKey);
        }

        char[] passphrase = passphraseProvider.getKeyPassword(signingKey);
        PGPKeyPair unlockedKey = signingKey.unlock(passphrase).getKeyPair();
        if (unlockedKey == null)
        {
            throw new KeyPassphraseException(signingKey, new PGPException("Cannot unlock secret key."));
        }

        return Utils.getPgpSignatureGenerator(implementation, signingKey.getPGPPublicKey(),
            unlockedKey.getPrivateKey(), parameters, null, null);
    }

    private int getPreferredHashAlgorithm(OpenPGPCertificate.OpenPGPComponentKey key)
    {
        // Determine the Hash Algorithm to use by inspecting the signing key's hash algorithm preferences
        // TODO: Instead inspect the hash algorithm preferences of recipient certificates?
        PreferredAlgorithms hashPreferences = key.getHashAlgorithmPreferences();
        if (hashPreferences != null)
        {
            int[] prefs = hashPreferences.getPreferences();
            List<Integer> acceptablePrefs = new ArrayList<Integer>();
            for (int i = 0; i < prefs.length; i++)
            {
                int algo = prefs[i];
                if (policy.isAcceptableDocumentSignatureHashAlgorithm(algo, new Date()))
                {
                    acceptablePrefs.add(algo);
                }
            }
            if (!acceptablePrefs.isEmpty())
            {
                return acceptablePrefs.get(0);
            }
        }
        return policy.getDefaultDocumentSignatureHashAlgorithm();
//        PreferredAlgorithms hashPreferences = key.getHashAlgorithmPreferences();
//        if (hashPreferences != null)
//        {
//            int[] pref = Arrays.stream(hashPreferences.getPreferences())
//                .filter(new IntPredicate()
//                { // Replace lambda with anonymous class for IntPredicate
//                    @Override
//                    public boolean test(int it)
//                    {
//                        return policy.isAcceptableDocumentSignatureHashAlgorithm(it, new Date());
//                    }
//                })
//                .toArray();
//            if (pref.length != 0)
//            {
//                return pref[0];
//            }
//        }
//        return policy.getDefaultDocumentSignatureHashAlgorithm();
    }

    /**
     * Set a callback that will be fired, if a passphrase for a protected signing key is missing.
     * This can be used for example to implement interactive on-demand passphrase prompting.
     *
     * @param callback passphrase provider
     * @return builder
     */
    public T setMissingKeyPassphraseCallback(KeyPassphraseProvider callback)
    {
        defaultKeyPassphraseProvider.setMissingPassphraseCallback(callback);
        return (T)this;
    }

    protected void addSignToGenerator()
        throws PGPException
    {
        for (int i = 0; i < signingKeys.size(); i++)
        {
            OpenPGPKey.OpenPGPSecretKey signingKey = signingKeys.get(i);
            KeyPassphraseProvider keyPassphraseProvider = signingKeyPassphraseProviders.get(i);
            SignatureParameters.Callback signatureCallback = signatureCallbacks.get(i);
            PGPSignatureGenerator sigGen = initSignatureGenerator(signingKey, keyPassphraseProvider, signatureCallback);
            signatureGenerators.add(sigGen);
        }
    }
}
