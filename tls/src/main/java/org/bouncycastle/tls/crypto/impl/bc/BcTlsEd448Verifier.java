package org.bouncycastle.tls.crypto.impl.bc;

import java.io.IOException;

import org.bouncycastle.crypto.params.Ed448PublicKeyParameters;
import org.bouncycastle.crypto.signers.Ed448Signer;
import org.bouncycastle.tls.DigitallySigned;
import org.bouncycastle.tls.HashAlgorithm;
import org.bouncycastle.tls.SignatureAlgorithm;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.tls.TlsUtils;
import org.bouncycastle.tls.crypto.TlsStreamVerifier;

public class BcTlsEd448Verifier
    extends BcTlsVerifier
{
    public BcTlsEd448Verifier(BcTlsCrypto crypto, Ed448PublicKeyParameters publicKey)
    {
        super(crypto, publicKey);
    }

    public boolean verifyRawSignature(DigitallySigned signature, byte[] hash) throws IOException
    {
        throw new UnsupportedOperationException();
    }

    public TlsStreamVerifier getStreamVerifier(DigitallySigned signature)
    {
        SignatureAndHashAlgorithm algorithm = signature.getAlgorithm();
        if (algorithm == null
            || algorithm.getSignature() != SignatureAlgorithm.ed448
            || algorithm.getHash() != HashAlgorithm.Intrinsic)
        {
            throw new IllegalStateException("Invalid algorithm: " + algorithm);
        }

        Ed448Signer verifier = new Ed448Signer(TlsUtils.EMPTY_BYTES);
        verifier.init(false, publicKey);

        return new BcTlsStreamVerifier(verifier, signature.getSignature());
    }
}
