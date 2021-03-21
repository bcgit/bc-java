package org.bouncycastle.tls.crypto.impl.bc;

import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.signers.SM2Signer;
import org.bouncycastle.tls.DigitallySigned;

/**
 * SM2 signature verifier
 *
 * force use SM2WithSM3 signature verify data.
 *
 *
 */
public class BcTlsSM2Verifier extends BcTlsVerifier
{
    protected BcTlsSM2Verifier(BcTlsCrypto crypto, ECPublicKeyParameters publicKey)
    {
        super(crypto, publicKey);
    }

    /**
     * verify signature
     *
     * @param signedParams signature
     * @param hash         raw message
     * @return true/false (pass or not)
     */
    public boolean verifyRawSignature(DigitallySigned signedParams, byte[] hash)
    {
        // ignore SignatureAndHashAlgorithm force use SM2WithSM3 signature alg.
        Signer signer = new SM2Signer();
        signer.init(false, publicKey);
        signer.update(hash, 0, hash.length);
        return signer.verifySignature(signedParams.getSignature());
    }
}
