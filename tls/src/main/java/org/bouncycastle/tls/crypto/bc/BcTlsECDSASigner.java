package org.bouncycastle.tls.crypto.bc;

import org.bouncycastle.crypto.DSA;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.signers.HMacDSAKCalculator;
import org.bouncycastle.tls.SignatureAlgorithm;
import org.bouncycastle.tls.TlsUtils;

public class BcTlsECDSASigner
    extends BcTlsDSASigner
{
    protected DSA createDSAImpl(short hashAlgorithm)
    {
        return new ECDSASigner(new HMacDSAKCalculator(BcTlsCrypto.createDigest(hashAlgorithm)));
    }

    protected short getSignatureAlgorithm()
    {
        return SignatureAlgorithm.ecdsa;
    }
}
