package org.bouncycastle.tls.crypto.impl.bc;

import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithID;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.signers.SM2Signer;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.tls.SignatureScheme;
import org.bouncycastle.tls.crypto.TlsStreamSigner;
import org.bouncycastle.util.Strings;

public class BcTlsSM2Signer
    extends BcTlsSigner
{
    protected final byte[] identifier;

    public BcTlsSM2Signer(BcTlsCrypto crypto, ECPrivateKeyParameters privateKey, int signatureScheme)
    {
        super(crypto, privateKey);

        if (SignatureScheme.sm2sig_sm3 != signatureScheme)
        {
            throw new IllegalArgumentException("signatureScheme");
        }

        this.identifier = Strings.toByteArray("TLSv1.3+GM+Cipher+Suite");
    }

    public TlsStreamSigner getStreamSigner(SignatureAndHashAlgorithm algorithm)
    {
        if (algorithm == null || SignatureScheme.from(algorithm) != SignatureScheme.sm2sig_sm3)
        {
            throw new IllegalStateException("Invalid algorithm: " + algorithm);
        }

        ParametersWithRandom parametersWithRandom = new ParametersWithRandom(privateKey, crypto.getSecureRandom());
        ParametersWithID parametersWithID = new ParametersWithID(parametersWithRandom, identifier);

        SM2Signer signer = new SM2Signer();
        signer.init(true, parametersWithID);

        return new BcTlsStreamSigner(signer);
    }
}
