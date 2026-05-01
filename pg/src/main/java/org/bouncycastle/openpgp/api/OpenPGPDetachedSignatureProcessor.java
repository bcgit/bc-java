package org.bouncycastle.openpgp.api;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;
import java.util.List;

import org.bouncycastle.bcpg.BCPGInputStream;
import org.bouncycastle.bcpg.KeyIdentifier;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureException;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.openpgp.PGPUtil;

/**
 * High-Level Processor for Messages Signed Using Detached OpenPGP Signatures.
 * <p>
 * To use this class, first instantiate the processor, optionally passing in a concrete
 * {@link OpenPGPImplementation} and {@link OpenPGPPolicy}.
 * Then, pass in any detached signatures you want to verify using {@link #addSignatures(InputStream)}.
 * Next, provide the expected issuers {@link OpenPGPCertificate OpenPGPCertificates} for signature
 * verification using {@link #addVerificationCertificate(OpenPGPCertificate)}.
 * Signatures for which no certificate was provided, and certificates for which no signature was added,
 * are ignored.
 * Optionally, you can specify a validity date range for the signatures using
 * {@link #verifyNotBefore(Date)} and {@link #verifyNotAfter(Date)}.
 * Signatures outside this range will be ignored as invalid.
 * Lastly, provide an {@link InputStream} containing the original plaintext data, over which you want to
 * verify the detached signatures using {@link #process(InputStream)}.
 * As a result you will receive a list containing all processed
 * {@link OpenPGPSignature.OpenPGPDocumentSignature OpenPGPDocumentSignatures}.
 * For these, you can check validity by calling {@link OpenPGPSignature.OpenPGPDocumentSignature#isValid()}.
 */
public class OpenPGPDetachedSignatureProcessor
{
    private final OpenPGPImplementation implementation;
    private final OpenPGPPolicy policy;
    private final OpenPGPKeyMaterialPool.OpenPGPCertificatePool certificatePool = new OpenPGPKeyMaterialPool.OpenPGPCertificatePool();
    private final List<PGPSignature> pgpSignatures = new ArrayList<PGPSignature>();
    private Date verifyNotAfter = new Date();       // now
    private Date verifyNotBefore = new Date(0L);    // beginning of time

    private OpenPGPMessageProcessor.PGPExceptionCallback exceptionCallback = null;

    /**
     * Instantiate a signature processor using the default {@link OpenPGPImplementation} and its {@link OpenPGPPolicy}.
     */
    public OpenPGPDetachedSignatureProcessor()
    {
        this(OpenPGPImplementation.getInstance());
    }

    /**
     * Instantiate a signature processor using a custom {@link OpenPGPImplementation} and its {@link OpenPGPPolicy}.
     *
     * @param implementation custom OpenPGP implementation
     */
    public OpenPGPDetachedSignatureProcessor(OpenPGPImplementation implementation)
    {
        this(implementation, implementation.policy());
    }

    /**
     * Instantiate a signature processor using a custom {@link OpenPGPImplementation} and custom {@link OpenPGPPolicy}.
     *
     * @param implementation custom OpenPGP implementation
     * @param policy         custom OpenPGP policy
     */
    public OpenPGPDetachedSignatureProcessor(OpenPGPImplementation implementation, OpenPGPPolicy policy)
    {
        this.implementation = implementation;
        this.policy = policy;
    }

    /**
     * Read one or more {@link PGPSignature detached signatures} from the provided {@link InputStream} and
     * add them to the processor.
     *
     * @param inputStream input stream of armored or unarmored detached OpenPGP signatures
     * @return this
     * @throws IOException if something goes wrong reading from the stream
     */
    public OpenPGPDetachedSignatureProcessor addSignatures(InputStream inputStream)
        throws IOException
    {
        InputStream decoderStream = PGPUtil.getDecoderStream(inputStream);
        BCPGInputStream pIn = BCPGInputStream.wrap(decoderStream);
        PGPObjectFactory objFac = implementation.pgpObjectFactory(pIn);
        Object next;
        while ((next = objFac.nextObject()) != null)
        {
            if (next instanceof PGPSignatureList)
            {
                addSignatures((PGPSignatureList)next);
            }
            else if (next instanceof PGPSignature)
            {
                addSignature((PGPSignature)next);
            }
        }
        return this;
    }

    /**
     * Add one or more {@link PGPSignature detached signatures} from the given {@link PGPSignatureList} to the
     * processor.
     *
     * @param signatures detached signature list
     * @return this
     */
    public OpenPGPDetachedSignatureProcessor addSignatures(PGPSignatureList signatures)
    {
        for (Iterator<PGPSignature> it = signatures.iterator(); it.hasNext(); )
        {
            addSignature(it.next());
        }
        return this;
    }

    /**
     * Add a single {@link PGPSignature detached signature} to the processor.
     *
     * @param signature detached signature
     * @return this
     */
    public OpenPGPDetachedSignatureProcessor addSignature(PGPSignature signature)
    {
        pgpSignatures.add(signature);
        return this;
    }

    /**
     * Add an issuers {@link OpenPGPCertificate} for signature verification.
     *
     * @param certificate OpenPGP certificate
     * @return this
     */
    public OpenPGPDetachedSignatureProcessor addVerificationCertificate(OpenPGPCertificate certificate)
    {
        this.certificatePool.addItem(certificate);
        return this;
    }

    /**
     * Reject detached signatures made before <pre>date</pre>.
     * By default, this value is set to the beginning of time.
     *
     * @param date date
     * @return this
     */
    public OpenPGPDetachedSignatureProcessor verifyNotBefore(Date date)
    {
        this.verifyNotBefore = date;
        return this;
    }

    /**
     * Reject detached signatures made after the given <pre>date</pre>.
     * By default, this value is set to the current time at instantiation time, in order to prevent
     * verification of signatures from the future.
     *
     * @param date date
     * @return this
     */
    public OpenPGPDetachedSignatureProcessor verifyNotAfter(Date date)
    {
        this.verifyNotAfter = date;
        return this;
    }

    /**
     * Process the plaintext data from the given {@link InputStream} and return a list of processed
     * detached signatures.
     * Note: This list will NOT contain any malformed signatures, or signatures for which no verification key was found.
     * Correctness of these signatures can be checked via {@link OpenPGPSignature.OpenPGPDocumentSignature#isValid()}.
     *
     * @param inputStream data over which the detached signatures are calculated
     * @return list of processed detached signatures
     * @throws IOException if the data cannot be processed
     */
    public List<OpenPGPSignature.OpenPGPDocumentSignature> process(InputStream inputStream)
        throws IOException
    {
        List<OpenPGPSignature.OpenPGPDocumentSignature> documentSignatures = new ArrayList<OpenPGPSignature.OpenPGPDocumentSignature>();
        for (Iterator it = pgpSignatures.iterator(); it.hasNext(); )
        {
            PGPSignature signature = (PGPSignature)it.next();
            // Match up signatures with certificates

            KeyIdentifier identifier = OpenPGPSignature.getMostExpressiveIdentifier(signature.getKeyIdentifiers());
            if (identifier == null)
            {
                // Missing issuer -> ignore sig
                continue;
            }

            OpenPGPCertificate certificate = certificatePool.provide(identifier);
            if (certificate == null)
            {
                // missing cert -> ignore sig
                continue;
            }

            OpenPGPCertificate.OpenPGPComponentKey signingKey = certificate.getKey(identifier);
            if (signingKey == null)
            {
                // unbound signing subkey -> ignore sig
                continue;
            }

            // Initialize signatures with verification key
            try
            {
                signature.init(implementation.pgpContentVerifierBuilderProvider(), signingKey.getPGPPublicKey());
            }
            catch (PGPException e)
            {
                if (exceptionCallback != null)
                {
                    exceptionCallback.onException(e);
                }
                continue;
            }

            OpenPGPSignature.OpenPGPDocumentSignature sig =
                new OpenPGPSignature.OpenPGPDocumentSignature(signature, signingKey);
            try
            {
                // sanitize signature (required subpackets, check algorithm policy...)
                sig.sanitize(signingKey, policy);
            }
            catch (PGPSignatureException e)
            {
                if (exceptionCallback != null)
                {
                    exceptionCallback.onException(e);
                }
                continue;
            }

            // check allowed date range
            if (!sig.createdInBounds(verifyNotBefore, verifyNotAfter))
            {
                continue;
            }

            // sig qualifies for further processing :)
            documentSignatures.add(sig);
        }

        // Process plaintext
        byte[] buf = new byte[2048];
        int r;
        while ((r = inputStream.read(buf)) != -1)
        {
            for (Iterator it = documentSignatures.iterator(); it.hasNext(); )
            {
                ((OpenPGPSignature.OpenPGPDocumentSignature)it.next()).getSignature().update(buf, 0, r);
            }
        }

        // Verify signatures
        for (Iterator it = documentSignatures.iterator(); it.hasNext(); )
        {
            try
            {
                // verify the signature. Correctness can be checked via
                ((OpenPGPSignature.OpenPGPDocumentSignature)it.next()).verify();
            }
            catch (PGPException e)
            {
                if (exceptionCallback != null)
                {
                    exceptionCallback.onException(e);
                }
            }
        }

        return documentSignatures;
    }

    /**
     * Add a callback to which any OpenPGP-related exceptions are forwarded.
     * Useful for debugging purposes.
     *
     * @param callback callback
     * @return this
     */
    public OpenPGPDetachedSignatureProcessor setExceptionCallback(OpenPGPMessageProcessor.PGPExceptionCallback callback)
    {
        this.exceptionCallback = callback;
        return this;
    }
}
