package org.bouncycastle.openpgp.api;

import org.bouncycastle.bcpg.sig.PreferredAlgorithms;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
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
 * calls to {@link #addSigningKey(OpenPGPKey, char[])}.
 * Lastly, retrieve a list of detached {@link OpenPGPSignature.OpenPGPDocumentSignature signatures} by calling
 * {@link #sign(InputStream)}, passing in an {@link InputStream} containing the data you want to sign.
 */
public class OpenPGPDetachedSignatureGenerator
{
    private final OpenPGPImplementation implementation;
    private final OpenPGPPolicy policy;
    private int signatureType = PGPSignature.BINARY_DOCUMENT;

    private final List<PGPSignatureGenerator> signatureGenerators = new ArrayList<>();
    private final List<OpenPGPCertificate.OpenPGPComponentKey> signingKeys = new ArrayList<>();

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

    /**
     * Set the type of generated signatures to {@link PGPSignature#BINARY_DOCUMENT}.
     * Binary signatures are calculated over the plaintext as is.
     * Binary signatures are the default.
     *
     * @return this
     */
    public OpenPGPDetachedSignatureGenerator setBinarySignature()
    {
        this.signatureType = PGPSignature.BINARY_DOCUMENT;
        return this;
    }

    /**
     * Set the type of generated signatures to {@link PGPSignature#CANONICAL_TEXT_DOCUMENT}.
     * Text signatures are calculated over modified plaintext, which is first transformed by canonicalizing
     * line endings to CR-LF (<pre>0x0D0A</pre>).
     * This is useful, if the plaintext is transported via a channel that may not retain the original message
     * encoding.
     *
     * @return this
     */
    public OpenPGPDetachedSignatureGenerator setCanonicalTextDocument()
    {
        this.signatureType = PGPSignature.CANONICAL_TEXT_DOCUMENT;
        return this;
    }

    /**
     * Add an {@link OpenPGPKey} as signing key.
     * If no (sub-)key in the signing key is capable of creating signatures, or if the key is expired or revoked,
     * this method will throw an {@link InvalidSigningKeyException}.
     * Otherwise, all capable signing subkeys will be used to create detached signatures.
     *
     * @param key OpenPGP key
     * @param passphrase passphrase to unlock the signing key
     * @return this
     *
     * @throws InvalidSigningKeyException if the OpenPGP key does not contain a usable signing subkey
     * @throws PGPException if signing fails
     */
    public OpenPGPDetachedSignatureGenerator addSigningKey(OpenPGPKey key, char[] passphrase)
            throws PGPException
    {
        List<OpenPGPCertificate.OpenPGPComponentKey> signingSubkeys = key.getSigningKeys();
        if (signingSubkeys.isEmpty())
        {
            throw new InvalidSigningKeyException("Key " + key.getPrettyFingerprint() + " cannot sign.");
        }
        OpenPGPKey.OpenPGPSecretKey signingKey = key.getSecretKey(signingSubkeys.get(0));

        PGPSignatureGenerator sigGen = new PGPSignatureGenerator(
                implementation.pgpContentSignerBuilder(
                        signingKey.getPublicKey().getPGPPublicKey().getAlgorithm(),
                        getPreferredHashAlgorithm(signingKey)),
                signingKey.getPGPPublicKey());
        sigGen.init(signatureType, signingKey.unlock(passphrase));

        signatureGenerators.add(sigGen);
        signingKeys.add(signingKey);

        return this;
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
