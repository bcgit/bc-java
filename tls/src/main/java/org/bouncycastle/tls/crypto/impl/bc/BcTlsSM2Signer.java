package org.bouncycastle.tls.crypto.impl.bc;

import java.io.IOException;

import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithID;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.signers.SM2Signer;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.tls.crypto.TlsStreamSigner;
import org.bouncycastle.util.Arrays;

public class BcTlsSM2Signer
    extends BcTlsSigner
{
    protected final byte[] identifier;

    public BcTlsSM2Signer(BcTlsCrypto crypto, ECPrivateKeyParameters privateKey, byte[] identifier)
    {
        super(crypto, privateKey);

        this.identifier = Arrays.clone(identifier);
    }

    public byte[] generateRawSignature(SignatureAndHashAlgorithm algorithm, byte[] hash) throws IOException
    {
        throw new UnsupportedOperationException();
    }

    public TlsStreamSigner getStreamSigner(SignatureAndHashAlgorithm algorithm)
    {
        if (algorithm == null
            // TODO[RFC 8998] 
//            || algorithm.getSignature() != SignatureAlgorithm.sm2
//            || algorithm.getHash() != HashAlgorithm.sm3
            )
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
