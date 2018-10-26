package org.bouncycastle.tls.crypto.impl.bc;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.Arrays;

import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.math.ec.rfc8032.Ed25519;
import org.bouncycastle.tls.HashAlgorithm;
import org.bouncycastle.tls.SignatureAlgorithm;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.tls.crypto.TlsStreamSigner;

public class BcTlsEd25519Signer
    extends BcTlsSigner
{
    protected final Ed25519PublicKeyParameters publicKey;

    public BcTlsEd25519Signer(BcTlsCrypto crypto, Ed25519PrivateKeyParameters privateKey, Ed25519PublicKeyParameters publicKey)
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
            || algorithm.getSignature() != SignatureAlgorithm.ed25519
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
                byte[] sk = new byte[Ed25519PrivateKeyParameters.KEY_SIZE];
                ((Ed25519PrivateKeyParameters)privateKey).encode(sk, 0);
                byte[] pk = publicKey.getEncoded();

                byte[] m = buf.toByteArray();

                byte[] sig = new byte[Ed25519.SIGNATURE_SIZE];
                Ed25519.sign(sk, 0, pk, 0, m, 0, m.length, sig, 0);
                Arrays.fill(sk, (byte)0);
                return sig;
            }
        };
    }
}
