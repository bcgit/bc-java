package org.bouncycastle.tls.crypto.impl.bc;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;

import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.math.ec.rfc8032.Ed25519;
import org.bouncycastle.tls.DigitallySigned;
import org.bouncycastle.tls.HashAlgorithm;
import org.bouncycastle.tls.SignatureAlgorithm;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.tls.crypto.TlsStreamVerifier;

public class BcTlsEd25519Verifier
    extends BcTlsVerifier
{
    public BcTlsEd25519Verifier(BcTlsCrypto crypto, Ed25519PublicKeyParameters publicKey)
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
            || algorithm.getSignature() != SignatureAlgorithm.ed25519
            || algorithm.getHash() != HashAlgorithm.Intrinsic)
        {
            throw new IllegalStateException();
        }

        final byte[] sig = signature.getSignature();
        final ByteArrayOutputStream buf = new ByteArrayOutputStream();

        return new TlsStreamVerifier()
        {
            public OutputStream getOutputStream()
            {
                return buf;
            }

            public boolean isVerified() throws IOException
            {
                byte[] pk = new byte[Ed25519PublicKeyParameters.KEY_SIZE];
                ((Ed25519PublicKeyParameters)publicKey).encode(pk, 0);

                byte[] m = buf.toByteArray();

                return Ed25519.verify(sig, 0, pk, 0, m, 0, m.length);
            }
        };
    }
}
