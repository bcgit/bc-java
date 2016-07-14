package org.bouncycastle.tls.crypto.bc;

import org.bouncycastle.crypto.DSA;
import org.bouncycastle.crypto.params.DSAPublicKeyParameters;
import org.bouncycastle.crypto.signers.DSASigner;
import org.bouncycastle.crypto.signers.HMacDSAKCalculator;
import org.bouncycastle.tls.SignatureAlgorithm;
import org.bouncycastle.tls.TlsUtils;

public class BcTlsDSSVerifier
    extends BcTlsDSAVerifier
{
    public BcTlsDSSVerifier(DSAPublicKeyParameters pubKeyDSA)
    {
        super(pubKeyDSA);
    }

    protected DSA createDSAImpl(short hashAlgorithm)
    {
        return new DSASigner(new HMacDSAKCalculator(TlsUtils.createHash(hashAlgorithm)));
    }

    protected short getSignatureAlgorithm()
    {
        return SignatureAlgorithm.dsa;
    }
}
