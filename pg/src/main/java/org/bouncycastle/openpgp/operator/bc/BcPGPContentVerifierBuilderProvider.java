package org.bouncycastle.openpgp.operator.bc;

import java.io.OutputStream;

import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.operator.PGPContentVerifier;
import org.bouncycastle.openpgp.operator.PGPContentVerifierBuilder;
import org.bouncycastle.openpgp.operator.PGPContentVerifierBuilderProvider;

public class BcPGPContentVerifierBuilderProvider
    implements PGPContentVerifierBuilderProvider
{
    private BcPGPKeyConverter keyConverter = new BcPGPKeyConverter();

    public BcPGPContentVerifierBuilderProvider()
    {
    }

    public PGPContentVerifierBuilder get(int keyAlgorithm, int hashAlgorithm)
        throws PGPException
    {
        return new BcPGPContentVerifierBuilder(keyAlgorithm, hashAlgorithm);
    }

    private class BcPGPContentVerifierBuilder
        implements PGPContentVerifierBuilder
    {
        private int hashAlgorithm;
        private int keyAlgorithm;

        public BcPGPContentVerifierBuilder(int keyAlgorithm, int hashAlgorithm)
        {
            this.keyAlgorithm = keyAlgorithm;
            this.hashAlgorithm = hashAlgorithm;
        }

        public PGPContentVerifier build(final PGPPublicKey publicKey)
            throws PGPException
        {
            AsymmetricKeyParameter pubParam = keyConverter.getPublicKey(publicKey);
            final Signer signer = BcImplProvider.createSigner(keyAlgorithm, hashAlgorithm, pubParam);

            signer.init(false, pubParam);

            return new PGPContentVerifier()
            {
                public int getHashAlgorithm()
                {
                    return hashAlgorithm;
                }

                public int getKeyAlgorithm()
                {
                    return keyAlgorithm;
                }

                public long getKeyID()
                {
                    return publicKey.getKeyID();
                }

                public boolean verify(byte[] expected)
                {
                    return signer.verifySignature(expected);
                }

                public OutputStream getOutputStream()
                {
                    return new SignerOutputStream(signer);
                }
            };
        }
    }
}
