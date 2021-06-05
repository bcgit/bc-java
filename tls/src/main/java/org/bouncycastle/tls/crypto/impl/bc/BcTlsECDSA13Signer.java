package org.bouncycastle.tls.crypto.impl.bc;

import java.io.IOException;

import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.DSA;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.digests.NullDigest;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.signers.DSADigestSigner;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.signers.HMacDSAKCalculator;
import org.bouncycastle.tls.AlertDescription;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.tls.SignatureScheme;
import org.bouncycastle.tls.TlsFatalAlert;

/**
 * Implementation class for generation of ECDSA signatures in TLS 1.3+ using the BC light-weight API.
 */
public class BcTlsECDSA13Signer
    extends BcTlsSigner
{
    private final int signatureScheme;

    public BcTlsECDSA13Signer(BcTlsCrypto crypto, ECPrivateKeyParameters privateKey, int signatureScheme)
    {
        super(crypto, privateKey);

        if (!SignatureScheme.isECDSA(signatureScheme))
        {
            throw new IllegalArgumentException("signatureScheme");
        }

        this.signatureScheme = signatureScheme;
    }

    public byte[] generateRawSignature(SignatureAndHashAlgorithm algorithm, byte[] hash) throws IOException
    {
        if (algorithm == null || SignatureScheme.from(algorithm) != signatureScheme)
        {
            throw new IllegalStateException("Invalid algorithm: " + algorithm);
        }

        int cryptoHashAlgorithm = SignatureScheme.getCryptoHashAlgorithm(signatureScheme);
        DSA dsa = new ECDSASigner(new HMacDSAKCalculator(crypto.createDigest(cryptoHashAlgorithm)));

        Signer signer = new DSADigestSigner(dsa, new NullDigest());
        signer.init(true, new ParametersWithRandom(privateKey, crypto.getSecureRandom()));
        signer.update(hash, 0, hash.length);
        try
        {
            return signer.generateSignature();
        }
        catch (CryptoException e)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error, e);
        }
    }
}
