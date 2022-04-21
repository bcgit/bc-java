package org.bouncycastle.tls.crypto.impl.bc;

import org.bouncycastle.crypto.DSA;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.tls.SignatureAlgorithm;

/**
 * Implementation class for the verification of the raw ECDSA signature type using the BC light-weight API.
 */
public class BcTlsECDSAVerifier
    extends BcTlsDSSVerifier
{
    public BcTlsECDSAVerifier(BcTlsCrypto crypto, ECPublicKeyParameters publicKey)
    {
        super(crypto, publicKey);
    }

    protected DSA createDSAImpl()
    {
        return new ECDSASigner();
    }

    protected short getSignatureAlgorithm()
    {
        return SignatureAlgorithm.ecdsa;
    }
}
