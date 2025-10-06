package org.bouncycastle.tls.crypto.impl.bc;

import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.pqc.crypto.MessageSignerAdapter;
import org.bouncycastle.pqc.crypto.slhdsa.SLHDSAPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.slhdsa.SLHDSASigner;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.tls.SignatureScheme;
import org.bouncycastle.tls.crypto.TlsStreamSigner;
import org.bouncycastle.tls.crypto.impl.PQCUtil;

public class BcTlsSLHDSASigner
    extends BcTlsSigner
{
    public static BcTlsSLHDSASigner create(BcTlsCrypto crypto, SLHDSAPrivateKeyParameters privateKey, int signatureScheme)
    {
        if (signatureScheme != PQCUtil.getSLHDSASignatureScheme(privateKey.getParameters()))
        {
            return null;
        }

        return new BcTlsSLHDSASigner(crypto, privateKey, signatureScheme);
    }

    private final int signatureScheme;

    private BcTlsSLHDSASigner(BcTlsCrypto crypto, SLHDSAPrivateKeyParameters privateKey, int signatureScheme)
    {
        super(crypto, privateKey);

        if (!SignatureScheme.isSLHDSA(signatureScheme))
        {
            throw new IllegalArgumentException("signatureScheme");
        }

        this.signatureScheme = signatureScheme;
    }

    public TlsStreamSigner getStreamSigner(SignatureAndHashAlgorithm algorithm)
    {
        if (algorithm == null || SignatureScheme.from(algorithm) != signatureScheme)
        {
            throw new IllegalStateException("Invalid algorithm: " + algorithm);
        }

        /*
         * draft-reddy-tls-slhdsa-01 2. [..], the context parameter [..] MUST be set to the empty string.
         */
        SLHDSASigner signer = new SLHDSASigner();
        signer.init(true, new ParametersWithRandom(privateKey, crypto.getSecureRandom()));

        return new BcTlsStreamSigner(new MessageSignerAdapter(signer));
    }
}
