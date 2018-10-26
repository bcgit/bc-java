package org.bouncycastle.tls.crypto.impl.bc;

import java.io.IOException;
import java.io.OutputStream;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.io.SignerOutputStream;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.signers.PSSSigner;
import org.bouncycastle.tls.DigitallySigned;
import org.bouncycastle.tls.HashAlgorithm;
import org.bouncycastle.tls.SignatureAlgorithm;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.tls.crypto.TlsStreamVerifier;

/**
 * Operator supporting the verification of RSASSA-PSS signatures using the BC light-weight API.
 */
public class BcTlsRSAPSSVerifier
    extends BcTlsVerifier
{
    private final short signatureAlgorithm;

    public BcTlsRSAPSSVerifier(BcTlsCrypto crypto, RSAKeyParameters publicKey, short signatureAlgorithm)
   {
        super(crypto, publicKey);

        if (!SignatureAlgorithm.isRSAPSS(signatureAlgorithm))
        {
            throw new IllegalArgumentException("signatureAlgorithm");
        }

        this.signatureAlgorithm = signatureAlgorithm;
    }

    public boolean verifyRawSignature(DigitallySigned signature, byte[] hash) throws IOException
    {
        throw new UnsupportedOperationException();
    }

    public TlsStreamVerifier getStreamVerifier(DigitallySigned signature)
    {
        SignatureAndHashAlgorithm algorithm = signature.getAlgorithm();
        if (algorithm == null
            || algorithm.getSignature() != signatureAlgorithm
            || algorithm.getHash() != HashAlgorithm.Intrinsic)
        {
            throw new IllegalStateException();
        }

        short hash = SignatureAlgorithm.getRSAPSSHashAlgorithm(signatureAlgorithm);
        Digest digest = crypto.createDigest(hash);

        PSSSigner signer = new PSSSigner(new RSAEngine(), digest, digest.getDigestSize());
        signer.init(false, publicKey);

        final byte[] sig = signature.getSignature();
        final SignerOutputStream sigOut = new SignerOutputStream(signer);

        return new TlsStreamVerifier()
        {
            public OutputStream getOutputStream()
            {
                return sigOut;
            }

            public boolean isVerified() throws IOException
            {
                return sigOut.getSigner().verifySignature(sig);
            }
        };
    }
}
