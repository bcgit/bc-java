package org.bouncycastle.openpgp.api;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;

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
        extends AbstractOpenPGPDocumentSignatureGenerator<OpenPGPDetachedSignatureGenerator>
{
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
        super(implementation, policy);
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
        addSignToGenerator();

        byte[] buf = new byte[2048];
        int r;
        while ((r = inputStream.read(buf)) != -1)
        {
            for (Iterator it = signatureGenerators.iterator(); it.hasNext();)
            {
                ((PGPSignatureGenerator) it.next()).update(buf, 0, r);
            }
        }

        List<OpenPGPSignature.OpenPGPDocumentSignature> documentSignatures = new ArrayList<OpenPGPSignature.OpenPGPDocumentSignature>();
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
