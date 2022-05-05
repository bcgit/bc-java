package org.bouncycastle.tls.crypto.impl;

import java.io.IOException;
import java.io.OutputStream;

import org.bouncycastle.tls.DigitallySigned;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.tls.SignatureScheme;
import org.bouncycastle.tls.TlsUtils;
import org.bouncycastle.tls.crypto.Tls13Verifier;
import org.bouncycastle.tls.crypto.TlsStreamVerifier;
import org.bouncycastle.tls.crypto.TlsVerifier;

public final class LegacyTls13Verifier
    implements TlsVerifier
{
    private final int signatureScheme;
    private final Tls13Verifier tls13Verifier;

    public LegacyTls13Verifier(int signatureScheme, Tls13Verifier tls13Verifier)
    {
        if (!TlsUtils.isValidUint16(signatureScheme))
        {
            throw new IllegalArgumentException("'signatureScheme'");
        }
        if (tls13Verifier == null)
        {
            throw new NullPointerException("'tls13Verifier' cannot be null");
        }

        this.signatureScheme = signatureScheme;
        this.tls13Verifier = tls13Verifier;
    }

    public TlsStreamVerifier getStreamVerifier(DigitallySigned digitallySigned) throws IOException
    {
        SignatureAndHashAlgorithm algorithm = digitallySigned.getAlgorithm();
        if (algorithm == null || SignatureScheme.from(algorithm) != signatureScheme)
        {
            throw new IllegalStateException("Invalid algorithm: " + algorithm);
        }

        final byte[] signature = digitallySigned.getSignature();

        return new TlsStreamVerifier()
        {
            public OutputStream getOutputStream() throws IOException
            {
                return tls13Verifier.getOutputStream();
            }

            public boolean isVerified() throws IOException
            {
                return tls13Verifier.verifySignature(signature);
            }
        };
    }

    public boolean verifyRawSignature(DigitallySigned digitallySigned, byte[] hash) throws IOException
    {
        throw new UnsupportedOperationException();
    }
}
