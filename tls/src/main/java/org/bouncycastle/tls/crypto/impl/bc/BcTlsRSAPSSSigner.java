package org.bouncycastle.tls.crypto.impl.bc;

import java.io.IOException;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.engines.RSABlindedEngine;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.signers.PSSSigner;
import org.bouncycastle.tls.HashAlgorithm;
import org.bouncycastle.tls.SignatureAlgorithm;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.tls.crypto.TlsStreamSigner;

/**
 * Operator supporting the generation of RSASSA-PSS signatures using the BC light-weight API.
 */
public class BcTlsRSAPSSSigner
    extends BcTlsSigner
{
    private final short signatureAlgorithm;

    public BcTlsRSAPSSSigner(BcTlsCrypto crypto, RSAKeyParameters privateKey, short signatureAlgorithm)
    {
        super(crypto, privateKey);

        if (!SignatureAlgorithm.isRSAPSS(signatureAlgorithm))
        {
            throw new IllegalArgumentException("signatureAlgorithm");
        }

        this.signatureAlgorithm = signatureAlgorithm;
    }

    public byte[] generateRawSignature(SignatureAndHashAlgorithm algorithm, byte[] hash) throws IOException
    {
        throw new UnsupportedOperationException();
    }

    public TlsStreamSigner getStreamSigner(SignatureAndHashAlgorithm algorithm)
    {
        if (algorithm == null
            || algorithm.getSignature() != signatureAlgorithm
            || algorithm.getHash() != HashAlgorithm.Intrinsic)
        {
            throw new IllegalStateException("Invalid algorithm: " + algorithm);
        }

        short hash = SignatureAlgorithm.getRSAPSSHashAlgorithm(signatureAlgorithm);
        Digest digest = crypto.createDigest(hash);

        PSSSigner signer = new PSSSigner(new RSABlindedEngine(), digest, HashAlgorithm.getOutputSize(hash));
        signer.init(true, new ParametersWithRandom(privateKey, crypto.getSecureRandom()));

        return new BcTlsStreamSigner(signer);
    }
}
