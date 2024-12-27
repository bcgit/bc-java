package org.bouncycastle.openpgp.api;

import org.bouncycastle.bcpg.BCPGInputStream;
import org.bouncycastle.bcpg.KeyIdentifier;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.openpgp.PGPUtil;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

public class OpenPGPDetachedSignatureProcessor
{

    private final OpenPGPImplementation implementation;
    private final OpenPGPKeyMaterialPool.OpenPGPCertificatePool certificatePool = new OpenPGPKeyMaterialPool.OpenPGPCertificatePool();
    private final List<PGPSignature> pgpSignatures = new ArrayList<>();
    private Date verifyNotAfter = new Date();       // now
    private Date verifyNotBefore = new Date(0L);    // beginning of time

    private OpenPGPMessageProcessor.PGPExceptionCallback exceptionCallback = null;

    public OpenPGPDetachedSignatureProcessor()
    {
        this(OpenPGPImplementation.getInstance());
    }

    public OpenPGPDetachedSignatureProcessor(OpenPGPImplementation implementation)
    {
        this.implementation = implementation;
    }

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
                PGPSignatureList signatureList = (PGPSignatureList) next;
                for (PGPSignature signature : signatureList)
                {
                    pgpSignatures.add(signature);
                }
            }
            else if (next instanceof PGPSignature)
            {
                PGPSignature signature = (PGPSignature) next;
                pgpSignatures.add(signature);
            }
        }
        return this;
    }

    public OpenPGPDetachedSignatureProcessor addVerificationCertificate(OpenPGPCertificate certificate)
    {
        this.certificatePool.addItem(certificate);
        return this;
    }

    public OpenPGPDetachedSignatureProcessor verifyNotBefore(Date date)
    {
        this.verifyNotBefore = date;
        return this;
    }

    public OpenPGPDetachedSignatureProcessor verifyNotAfter(Date date)
    {
        this.verifyNotAfter = date;
        return this;
    }

    public List<OpenPGPSignature.OpenPGPDocumentSignature> verify(InputStream inputStream)
            throws IOException
    {
        List<OpenPGPSignature.OpenPGPDocumentSignature> documentSignatures = new ArrayList<>();
        for (PGPSignature signature : pgpSignatures)
        {
            // Match up signatures with certificates

            KeyIdentifier identifier = OpenPGPSignature.getMostExpressiveIdentifier(signature.getKeyIdentifiers());
            if (identifier == null)
            {
                continue;
            }

            OpenPGPCertificate certificate = certificatePool.provide(identifier);
            if (certificate == null)
            {
                continue;
            }

            OpenPGPCertificate.OpenPGPComponentKey signingKey = certificate.getKey(identifier);
            if (signingKey == null)
            {
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
            }

            OpenPGPSignature.OpenPGPDocumentSignature sig =
                    new OpenPGPSignature.OpenPGPDocumentSignature(signature, signingKey);
            if (!sig.createdInBounds(verifyNotBefore, verifyNotAfter))
            {
                continue;
            }
            documentSignatures.add(sig);
        }

        // Process plaintext
        byte[] buf = new byte[2048];
        int r;
        while ((r = inputStream.read(buf)) != -1)
        {
            for (OpenPGPSignature.OpenPGPDocumentSignature sig : documentSignatures)
            {
                sig.getSignature().update(buf, 0, r);
            }
        }

        // Verify signatures
        for (OpenPGPSignature.OpenPGPDocumentSignature sig : documentSignatures)
        {
            try
            {
                sig.verify();
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

    public OpenPGPDetachedSignatureProcessor setExceptionCallback(OpenPGPMessageProcessor.PGPExceptionCallback callback)
    {
        this.exceptionCallback = callback;
        return this;
    }
}
