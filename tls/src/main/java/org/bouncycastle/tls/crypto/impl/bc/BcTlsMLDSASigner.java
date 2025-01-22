package org.bouncycastle.tls.crypto.impl.bc;

import java.io.IOException;

import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSASigner;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.tls.SignatureScheme;
import org.bouncycastle.tls.crypto.TlsStreamSigner;
import org.bouncycastle.tls.crypto.impl.PQCUtil;

public class BcTlsMLDSASigner
    extends BcTlsSigner
{
    public static BcTlsMLDSASigner create(BcTlsCrypto crypto, MLDSAPrivateKeyParameters privateKey, int signatureScheme)
    {
        if (signatureScheme != PQCUtil.getMLDSASignatureScheme(privateKey.getParameters()))
        {
            return null;
        }

        return new BcTlsMLDSASigner(crypto, privateKey, signatureScheme);
    }

    private final int signatureScheme;

    private BcTlsMLDSASigner(BcTlsCrypto crypto, MLDSAPrivateKeyParameters privateKey, int signatureScheme)
    {
        super(crypto, privateKey);

        this.signatureScheme = signatureScheme;
    }

    public byte[] generateRawSignature(SignatureAndHashAlgorithm algorithm, byte[] hash) throws IOException
    {
        throw new UnsupportedOperationException();
    }

    public TlsStreamSigner getStreamSigner(SignatureAndHashAlgorithm algorithm)
    {
        if (algorithm == null || SignatureScheme.from(algorithm) != signatureScheme)
        {
            throw new IllegalStateException("Invalid algorithm: " + algorithm);
        }

        MLDSASigner signer = new MLDSASigner();
        signer.init(true, new ParametersWithRandom(privateKey, crypto.getSecureRandom()));

        return new BcTlsStreamSigner(signer);
    }
}
