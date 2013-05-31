package org.bouncycastle.openpgp.operator.bc;

import java.io.OutputStream;
import java.security.SecureRandom;

import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.operator.PGPContentSigner;
import org.bouncycastle.openpgp.operator.PGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.util.io.TeeOutputStream;

public class BcPGPContentSignerBuilder
    implements PGPContentSignerBuilder
{
    private BcPGPDigestCalculatorProvider digestCalculatorProvider = new BcPGPDigestCalculatorProvider();
    private BcPGPKeyConverter           keyConverter = new BcPGPKeyConverter();
    private int                         hashAlgorithm;
    private SecureRandom                random;
    private int keyAlgorithm;

    public BcPGPContentSignerBuilder(int keyAlgorithm, int hashAlgorithm)
    {
        this.keyAlgorithm = keyAlgorithm;
        this.hashAlgorithm = hashAlgorithm;
    }

    public BcPGPContentSignerBuilder setSecureRandom(SecureRandom random)
    {
        this.random = random;

        return this;
    }

    public PGPContentSigner build(final int signatureType, final PGPPrivateKey privateKey)
        throws PGPException
    {
        final PGPDigestCalculator digestCalculator = digestCalculatorProvider.get(hashAlgorithm);
        final Signer signer = BcImplProvider.createSigner(keyAlgorithm, hashAlgorithm);

        if (random != null)
        {
            signer.init(true, new ParametersWithRandom(keyConverter.getPrivateKey(privateKey), random));
        }
        else
        {
            signer.init(true, keyConverter.getPrivateKey(privateKey));
        }

        return new PGPContentSigner()
        {
            public int getType()
            {
                return signatureType;
            }

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
                return privateKey.getKeyID();
            }

            public OutputStream getOutputStream()
            {
                return new TeeOutputStream(new SignerOutputStream(signer), digestCalculator.getOutputStream());
            }

            public byte[] getSignature()
            {
                try
                {
                    return signer.generateSignature();
                }
                catch (CryptoException e)
                {    // TODO: need a specific runtime exception for PGP operators.
                    throw new IllegalStateException("unable to create signature");
                }
            }

            public byte[] getDigest()
            {
                return digestCalculator.getDigest();
            }
        };
    }
}
