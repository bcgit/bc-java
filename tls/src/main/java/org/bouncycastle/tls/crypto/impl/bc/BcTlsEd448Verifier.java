package org.bouncycastle.tls.crypto.impl.bc;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;

import org.bouncycastle.crypto.params.Ed448PublicKeyParameters;
import org.bouncycastle.math.ec.rfc8032.Ed448;
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
                byte[] pk = new byte[Ed448PublicKeyParameters.KEY_SIZE];
                ((Ed448PublicKeyParameters)publicKey).encode(pk, 0);

                byte[] ctx = TlsUtils.EMPTY_BYTES;
                byte[] m = buf.toByteArray();

                return Ed448.verify(sig, 0, pk, 0, ctx, m, 0, m.length);
            }
        };
    }
}
