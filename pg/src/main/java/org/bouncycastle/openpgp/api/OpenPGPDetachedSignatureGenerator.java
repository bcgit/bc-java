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

public class OpenPGPDetachedSignatureGenerator
{
    private final OpenPGPImplementation implementation;
    private final OpenPGPPolicy policy;
    private int signatureType = PGPSignature.BINARY_DOCUMENT;

    private final List<PGPSignatureGenerator> signatureGenerators = new ArrayList<>();
    private final List<OpenPGPCertificate.OpenPGPComponentKey> signingKeys = new ArrayList<>();

    public OpenPGPDetachedSignatureGenerator()
    {
        this(OpenPGPImplementation.getInstance());
    }

    public OpenPGPDetachedSignatureGenerator(OpenPGPImplementation implementation)
    {
        this(implementation, implementation.policy());
    }

    public OpenPGPDetachedSignatureGenerator(OpenPGPImplementation implementation, OpenPGPPolicy policy)
    {
        this.implementation = implementation;
        this.policy = policy;
    }

    public OpenPGPDetachedSignatureGenerator setBinarySignature()
    {
        this.signatureType = PGPSignature.BINARY_DOCUMENT;
        return this;
    }

    public OpenPGPDetachedSignatureGenerator setCanonicalTextDocument()
    {
        this.signatureType = PGPSignature.CANONICAL_TEXT_DOCUMENT;
        return this;
    }

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
