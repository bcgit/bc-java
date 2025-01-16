package org.bouncycastle.openpgp.api;

import org.bouncycastle.bcpg.sig.PreferredAlgorithms;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.bouncycastle.openpgp.api.exception.InvalidSigningKeyException;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

/**
 * High-Level OpenPGP Signature Generator for Detached Signatures.
 * Detached signatures can be stored and distributed as a distinct object alongside the signed data.
 * They are used for example to sign Release files of some Linux software distributions.
 * <p>
 * To use this class, instantiate it, optionally providing a concrete {@link OpenPGPImplementation} and
 * {@link OpenPGPPolicy} for algorithm policing.
 * Then, add the desired {@link OpenPGPKey} you want to use for signing the data via one or more
 * calls to {@link #addSigningKey(OpenPGPKey, KeyPassphraseProvider)}.
 * You have fine-grained control over the signature by using the method
 * {@link #addSigningKey(OpenPGPKey.OpenPGPSecretKey, char[], SignatureParameters.Callback)}.
 * Lastly, retrieve a list of detached {@link OpenPGPSignature.OpenPGPDocumentSignature signatures} by calling
 * {@link #sign(InputStream)}, passing in an {@link InputStream} containing the data you want to sign.
 */
public class OpenPGPDetachedSignatureGenerator
{
    private final OpenPGPImplementation implementation;
    private final OpenPGPPolicy policy;

    // Below lists all use the same indexing
    private final List<PGPSignatureGenerator> signatureGenerators = new ArrayList<>();
    private final List<OpenPGPKey.OpenPGPSecretKey> signingKeys = new ArrayList<>();
    private final List<SignatureParameters.Callback> signatureCallbacks = new ArrayList<>();
    private final List<KeyPassphraseProvider> signingKeyPassphraseProviders = new ArrayList<>();

    private final KeyPassphraseProvider.DefaultKeyPassphraseProvider defaultKeyPassphraseProvider =
            new KeyPassphraseProvider.DefaultKeyPassphraseProvider();

    /**
     * Instantiate a signature generator using the default {@link OpenPGPImplementation} and its {@link OpenPGPPolicy}.
     */
    public OpenPGPDetachedSignatureGenerator()
    {
        this(OpenPGPImplementation.getInstance());
    }

    /**
     * Instantiate a signature generator using the passed in {@link OpenPGPImplementation} and its {@link OpenPGPPolicy}.
     *
     * @param implementation custom OpenPGP implementation
     */
    public OpenPGPDetachedSignatureGenerator(OpenPGPImplementation implementation)
    {
        this(implementation, implementation.policy());
    }

    /**
     * Instantiate a signature generator using a custom {@link OpenPGPImplementation} and custom {@link OpenPGPPolicy}.
     *
     * @param implementation custom OpenPGP implementation
     * @param policy custom OpenPGP policy
     */
    public OpenPGPDetachedSignatureGenerator(OpenPGPImplementation implementation, OpenPGPPolicy policy)
    {
        this.implementation = implementation;
        this.policy = policy;
    }

    public OpenPGPDetachedSignatureGenerator addKeyPassphrase(char[] passphrase)
    {
        defaultKeyPassphraseProvider.addPassphrase(passphrase);
        return this;
    }

    public OpenPGPDetachedSignatureGenerator addSigningKey(
            OpenPGPKey key)
        throws PGPException
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
    public OpenPGPDetachedSignatureGenerator addSigningKey(
            OpenPGPKey key,
            KeyPassphraseProvider passphraseProvider)
            throws PGPException
    {
        List<OpenPGPCertificate.OpenPGPComponentKey> signingSubkeys = key.getSigningKeys();
        if (signingSubkeys.isEmpty())
        {
            throw new InvalidSigningKeyException("Key " + key.getPrettyFingerprint() + " cannot sign.");
        }
        OpenPGPKey.OpenPGPSecretKey signingKey = key.getSecretKey(signingSubkeys.get(0));

        return addSigningKey(signingKey, passphraseProvider, null);
    }

    public OpenPGPDetachedSignatureGenerator addSigningKey(
            OpenPGPKey.OpenPGPSecretKey signingKey,
            char[] passphrase,
            SignatureParameters.Callback signatureCallback)
            throws PGPException
    {
        return addSigningKey(
                signingKey,
                defaultKeyPassphraseProvider.addPassphrase(signingKey, passphrase),
                signatureCallback);
    }

    public OpenPGPDetachedSignatureGenerator addSigningKey(
            OpenPGPKey.OpenPGPSecretKey signingKey,
            KeyPassphraseProvider passphraseProvider,
            SignatureParameters.Callback signatureCallback)
            throws PGPException
    {
        if (!signingKey.isSigningKey())
        {
            throw new InvalidSigningKeyException("Subkey cannot sign.");
        }

        signingKeys.add(signingKey);
        signingKeyPassphraseProviders.add(passphraseProvider);
        signatureCallbacks.add(signatureCallback);
        return this;
    }

    private PGPSignatureGenerator initSignatureGenerator(
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

    /**
     * Pass in an {@link InputStream} containing the data that shall be signed and return a list of detached
     * signatures.
     *
     * @param inputStream data to be signed
     * @return detached signatures
     *
     * @throws IOException if something goes wrong processing the data
     * @throws PGPException if signing fails
     */
    public List<OpenPGPSignature.OpenPGPDocumentSignature> sign(InputStream inputStream)
            throws IOException, PGPException
    {
        for (int i = 0; i < signingKeys.size(); i++)
        {
            OpenPGPKey.OpenPGPSecretKey signingKey = signingKeys.get(i);
            KeyPassphraseProvider passphraseProvider = signingKeyPassphraseProviders.get(i);
            SignatureParameters.Callback signatureCallback = signatureCallbacks.get(i);
            PGPSignatureGenerator signatureGenerator =
                    initSignatureGenerator(signingKey, passphraseProvider, signatureCallback);
            signatureGenerators.add(signatureGenerator);
        }

        byte[] buf = new byte[2048];
        int r;
        while ((r = inputStream.read(buf)) != -1)
        {
            for (PGPSignatureGenerator sigGen : signatureGenerators)
            {
                sigGen.update(buf, 0, r);
            }
        }

        List<OpenPGPSignature.OpenPGPDocumentSignature> documentSignatures = new ArrayList<>();
        for (int i = 0; i < signatureGenerators.size(); i++)
        {
            PGPSignatureGenerator sigGen = signatureGenerators.get(i);
            PGPSignature signature = sigGen.generate();
            OpenPGPSignature.OpenPGPDocumentSignature docSig = new OpenPGPSignature.OpenPGPDocumentSignature(
                    signature, signingKeys.get(i));
            documentSignatures.add(docSig);
        }

        return documentSignatures;
    }
}
