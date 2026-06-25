package org.bouncycastle.crypto.agreement;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.params.ECDHUPrivateParameters;
import org.bouncycastle.crypto.params.ECDHUPublicParameters;

/**
 * EC Unified static/ephemeral agreement as described in NIST SP 800-56A using EC co-factor Diffie-Hellman.
 */
public class ECDHCUnifiedAgreement
{
    private ECDHUPrivateParameters privParams;

    public void init(
        CipherParameters key)
    {
        this.privParams = (ECDHUPrivateParameters)key;

        CryptoServicesRegistrar.checkConstraints(Utils.getDefaultProperties("ECCDHU", this.privParams.getStaticPrivateKey()));
    }

    public int getFieldSize()
    {
        return privParams.getStaticPrivateKey().getParameters().getCurve().getFieldElementEncodingLength();
    }

    public byte[] calculateAgreement(CipherParameters pubKey)
    {
        ECDHUPublicParameters pubParams = (ECDHUPublicParameters)pubKey;

        ECDHCRawAgreement ecDHC = new ECDHCRawAgreement();

        int fieldSize = getFieldSize();
        byte[] result = new byte[fieldSize * 2];

        ecDHC.init(privParams.getStaticPrivateKey());
        ecDHC.calculateAgreement(pubParams.getStaticPublicKey(), result, fieldSize);

        ecDHC.init(privParams.getEphemeralPrivateKey());
        ecDHC.calculateAgreement(pubParams.getEphemeralPublicKey(), result, 0);

        return result;
    }
}
