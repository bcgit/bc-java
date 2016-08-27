package org.bouncycastle.tls.crypto.bc;

import org.bouncycastle.crypto.DSA;
import org.bouncycastle.crypto.signers.DSASigner;
import org.bouncycastle.crypto.signers.HMacDSAKCalculator;
import org.bouncycastle.tls.SignatureAlgorithm;

public class BcTlsDSSSigner
    extends BcTlsDSASigner
{
    protected DSA createDSAImpl(short hashAlgorithm)
    {
        return new DSASigner(new HMacDSAKCalculator(BcTlsCrypto.createDigest(hashAlgorithm)));
    }

    protected short getSignatureAlgorithm()
    {
        return SignatureAlgorithm.dsa;
    }
}
