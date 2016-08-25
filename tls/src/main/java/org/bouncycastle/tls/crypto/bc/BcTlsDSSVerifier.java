package org.bouncycastle.tls.crypto.bc;

import org.bouncycastle.crypto.DSA;
import org.bouncycastle.crypto.params.DSAPublicKeyParameters;
import org.bouncycastle.crypto.signers.DSASigner;
import org.bouncycastle.crypto.signers.HMacDSAKCalculator;
import org.bouncycastle.tls.SignatureAlgorithm;

public class BcTlsDSSVerifier
    extends BcTlsDSAVerifier
{
    public BcTlsDSSVerifier(BcTlsCrypto crypto, DSAPublicKeyParameters pubKeyDSA)
    {
        super(crypto, pubKeyDSA);
    }

    protected DSA createDSAImpl(short hashAlgorithm)
    {
        return new DSASigner(new HMacDSAKCalculator(crypto.createHash(hashAlgorithm)));
    }

    protected short getSignatureAlgorithm()
    {
        return SignatureAlgorithm.dsa;
    }
}
