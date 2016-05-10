package com.github.gv2011.bcasn.crypto.tls;

import com.github.gv2011.bcasn.crypto.DSA;
import com.github.gv2011.bcasn.crypto.params.AsymmetricKeyParameter;
import com.github.gv2011.bcasn.crypto.params.ECPublicKeyParameters;
import com.github.gv2011.bcasn.crypto.signers.ECDSASigner;
import com.github.gv2011.bcasn.crypto.signers.HMacDSAKCalculator;

public class TlsECDSASigner
    extends TlsDSASigner
{
    public boolean isValidPublicKey(AsymmetricKeyParameter publicKey)
    {
        return publicKey instanceof ECPublicKeyParameters;
    }

    protected DSA createDSAImpl(short hashAlgorithm)
    {
        return new ECDSASigner(new HMacDSAKCalculator(TlsUtils.createHash(hashAlgorithm)));
    }

    protected short getSignatureAlgorithm()
    {
        return SignatureAlgorithm.ecdsa;
    }
}
