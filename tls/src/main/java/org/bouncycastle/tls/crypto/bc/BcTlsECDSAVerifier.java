package org.bouncycastle.tls.crypto.bc;

import org.bouncycastle.crypto.DSA;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.signers.HMacDSAKCalculator;
import org.bouncycastle.tls.SignatureAlgorithm;
import org.bouncycastle.tls.TlsUtils;

public class BcTlsECDSAVerifier
    extends BcTlsDSAVerifier
{
    public BcTlsECDSAVerifier(BcTlsCrypto crypto, ECPublicKeyParameters pubKeyEC)
    {
        super(crypto, pubKeyEC);
    }

    protected DSA createDSAImpl(short hashAlgorithm)
    {
        return new ECDSASigner(new HMacDSAKCalculator(crypto.createHash(hashAlgorithm)));
    }

    protected short getSignatureAlgorithm()
    {
        return SignatureAlgorithm.ecdsa;
    }
}
