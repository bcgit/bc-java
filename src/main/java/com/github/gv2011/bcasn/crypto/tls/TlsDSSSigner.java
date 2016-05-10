package com.github.gv2011.bcasn.crypto.tls;

import com.github.gv2011.bcasn.crypto.DSA;
import com.github.gv2011.bcasn.crypto.params.AsymmetricKeyParameter;
import com.github.gv2011.bcasn.crypto.params.DSAPublicKeyParameters;
import com.github.gv2011.bcasn.crypto.signers.DSASigner;
import com.github.gv2011.bcasn.crypto.signers.HMacDSAKCalculator;

public class TlsDSSSigner
    extends TlsDSASigner
{
    public boolean isValidPublicKey(AsymmetricKeyParameter publicKey)
    {
        return publicKey instanceof DSAPublicKeyParameters;
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
