package org.bouncycastle.tls.crypto.impl.bc;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.Arrays;

import org.bouncycastle.crypto.params.Ed448PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed448PublicKeyParameters;
import org.bouncycastle.math.ec.rfc8032.Ed448;
import org.bouncycastle.tls.HashAlgorithm;
import org.bouncycastle.tls.SignatureAlgorithm;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.tls.TlsUtils;
import org.bouncycastle.tls.crypto.TlsStreamSigner;

public class BcTlsEd448Signer
    extends BcTlsSigner
{
    protected final Ed448PublicKeyParameters publicKey;

    public BcTlsEd448Signer(BcTlsCrypto crypto, Ed448PrivateKeyParameters privateKey, Ed448PublicKeyParameters publicKey)
    {
        super(crypto, privateKey);

        this.publicKey = publicKey != null ? publicKey : privateKey.generatePublicKey();
    }

    public byte[] generateRawSignature(SignatureAndHashAlgorithm algorithm, byte[] hash) throws IOException
    {
        throw new UnsupportedOperationException();
    }

    public TlsStreamSigner getStreamSigner(SignatureAndHashAlgorithm algorithm)
    {
        if (algorithm == null
            || algorithm.getSignature() != SignatureAlgorithm.ed448
            || algorithm.getHash() != HashAlgorithm.Intrinsic)
        {
            throw new IllegalStateException();
        }

        final ByteArrayOutputStream buf = new ByteArrayOutputStream();

        return new TlsStreamSigner()
        {
            public OutputStream getOutputStream()
            {
                return buf;
            }

            public byte[] getSignature() throws IOException
            {
                byte[] sk = new byte[Ed448PrivateKeyParameters.KEY_SIZE];
                ((Ed448PrivateKeyParameters)privateKey).encode(sk, 0);
                byte[] pk = publicKey.getEncoded();

                byte[] ctx = TlsUtils.EMPTY_BYTES;
                byte[] m = buf.toByteArray();

                byte[] sig = new byte[Ed448.SIGNATURE_SIZE];
                Ed448.sign(sk, 0, pk, 0, ctx, m, 0, m.length, sig, 0);
                Arrays.fill(sk, (byte)0);
                return sig;
            }
        };
    }
}
