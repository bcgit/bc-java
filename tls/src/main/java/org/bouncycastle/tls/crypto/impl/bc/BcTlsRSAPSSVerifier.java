package org.bouncycastle.tls.crypto.impl.bc;

import java.io.IOException;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.signers.PSSSigner;
import org.bouncycastle.tls.DigitallySigned;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.tls.SignatureScheme;

/**
 * Operator supporting the verification of RSASSA-PSS signatures using the BC light-weight API.
 */
public class BcTlsRSAPSSVerifier
    extends BcTlsVerifier
{
    private final int signatureScheme;

    public BcTlsRSAPSSVerifier(BcTlsCrypto crypto, RSAKeyParameters publicKey, int signatureScheme)
    {
        super(crypto, publicKey);

        if (!SignatureScheme.isRSAPSS(signatureScheme))
        {
            throw new IllegalArgumentException("signatureScheme");
        }

        this.signatureScheme = signatureScheme;
    }

    public boolean verifyRawSignature(DigitallySigned digitallySigned, byte[] hash) throws IOException
    {
        SignatureAndHashAlgorithm algorithm = digitallySigned.getAlgorithm();
        if (algorithm == null || SignatureScheme.from(algorithm) != signatureScheme)
        {
            throw new IllegalStateException("Invalid algorithm: " + algorithm);
        }

        int cryptoHashAlgorithm = SignatureScheme.getCryptoHashAlgorithm(signatureScheme);
        Digest digest = crypto.createDigest(cryptoHashAlgorithm);

        PSSSigner verifier = PSSSigner.createRawSigner(new RSAEngine(), digest, digest, digest.getDigestSize(),
            PSSSigner.TRAILER_IMPLICIT);
        verifier.init(false, publicKey);
        verifier.update(hash, 0, hash.length);
        return verifier.verifySignature(digitallySigned.getSignature());
    }
}
