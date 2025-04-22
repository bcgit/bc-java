package org.bouncycastle.openpgp.api;

import java.io.IOException;
import java.util.Date;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;

class Utils
{
    static void addEmbeddedSiganture(final PGPSignature backSig, PGPSignatureSubpacketGenerator hashedSubpackets)
        throws PGPException
    {
        if (backSig != null)
        {
            try
            {
                hashedSubpackets.addEmbeddedSignature(true, backSig);
            }
            catch (IOException e)
            {
                throw new PGPException("Cannot encode embedded back-signature.", e);
            }
        }
    }

    static PGPSignature getBackSignature(PGPKeyPair signingSubkey, SignatureParameters backSigParameters,
                                         PGPPublicKey publicPrimaryKey, OpenPGPImplementation implementation, Date date)
        throws PGPException
    {
        PGPSignature backSig = null;
        if (backSigParameters != null)
        {
            PGPSignatureGenerator backSigGen = getPgpSignatureGenerator(implementation, signingSubkey.getPublicKey(),
                signingSubkey.getPrivateKey(), backSigParameters, date, null);

            backSig = backSigGen.generateCertification(publicPrimaryKey, signingSubkey.getPublicKey());
        }
        return backSig;
    }

    static PGPPublicKey injectCertification(PGPPublicKey publicKey, PGPSignatureGenerator revGen, PGPPublicKey publicPrimaryKey)
        throws PGPException
    {
        PGPSignature revocation = revGen.generateCertification(publicPrimaryKey, publicKey);
        return PGPPublicKey.addCertification(publicKey, revocation);
    }

    static PGPPublicKey injectCertification(PGPPublicKey publicKey, PGPSignatureGenerator revGen)
        throws PGPException
    {
        // Inject signature into the certificate
        PGPSignature revocation = revGen.generateCertification(publicKey);
        return PGPPublicKey.addCertification(publicKey, revocation);
    }

    static PGPPublicKey injectCertification(String userId, PGPPublicKey publicPrimaryKey, PGPSignatureGenerator uidSigGen)
        throws PGPException
    {
        // Inject UID and signature into the certificate
        PGPSignature uidSig = uidSigGen.generateCertification(userId, publicPrimaryKey);
        return PGPPublicKey.addCertification(publicPrimaryKey, userId, uidSig);
    }

    public interface HashedSubpacketsOperation
    {
        void operate(PGPSignatureSubpacketGenerator hashedSubpackets)
            throws PGPException;
    }

    static PGPSignatureGenerator getPgpSignatureGenerator(OpenPGPImplementation implementationProvider,
                                                          PGPPublicKey publicKey,
                                                          PGPPrivateKey privateKey,
                                                          SignatureParameters parameters,
                                                          Date date,
                                                          HashedSubpacketsOperation operation)
        throws PGPException
    {
        PGPSignatureGenerator sigGen = new PGPSignatureGenerator(
            implementationProvider.pgpContentSignerBuilder(
                publicKey.getAlgorithm(),
                parameters.getSignatureHashAlgorithmId()),
            publicKey);
        sigGen.init(parameters.getSignatureType(), privateKey);

        final PGPSignatureSubpacketGenerator hashedSubpackets = new PGPSignatureSubpacketGenerator();
        hashedSubpackets.setIssuerFingerprint(true, publicKey);
        if (date != null)
        {
            hashedSubpackets.setSignatureCreationTime(date);
        }
        if (operation != null)
        {
            operation.operate(hashedSubpackets);
        }
        parameters.applyToHashedSubpackets(hashedSubpackets);
        sigGen.setHashedSubpackets(hashedSubpackets.generate());

        PGPSignatureSubpacketGenerator unhashedSubpackets = new PGPSignatureSubpacketGenerator();
        unhashedSubpackets = parameters.applyToUnhashedSubpackets(unhashedSubpackets);
        sigGen.setUnhashedSubpackets(unhashedSubpackets.generate());
        return sigGen;
    }

    static SignatureParameters applySignatureParameters(SignatureParameters.Callback signatureCallback, SignatureParameters parameters)
    {
        if (signatureCallback != null)
        {
            parameters = signatureCallback.apply(parameters);
        }
        return parameters;
    }
}
