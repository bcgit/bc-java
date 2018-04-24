package org.bouncycastle.tls.crypto.impl.bc;

import org.bouncycastle.crypto.DSA;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.signers.HMacDSAKCalculator;
import org.bouncycastle.tls.SignatureAlgorithm;

/**
 * Implementation class for generation of the raw ECDSA signature type using the BC light-weight API.
 */
public class BcTlsECDSASigner
    extends BcTlsDSSSigner
{
    public BcTlsECDSASigner(BcTlsCrypto crypto, ECPrivateKeyParameters privateKey)
    {
        super(crypto, privateKey);
    }

    protected DSA createDSAImpl(short hashAlgorithm)
    {
        return new ECDSASigner(new HMacDSAKCalculator(crypto.createDigest(hashAlgorithm)));
    }

    protected short getSignatureAlgorithm()
    {
        return SignatureAlgorithm.ecdsa;
    }
}
