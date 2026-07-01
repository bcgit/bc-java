package org.bouncycastle.crypto.agreement;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.RawAgreement;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;

public final class ECDHRawAgreement
    implements RawAgreement
{
    private ECPrivateKeyParameters privateKey;

    public void init(CipherParameters parameters)
    {
        this.privateKey = (ECPrivateKeyParameters)parameters;

        CryptoServicesRegistrar.checkConstraints(Utils.getDefaultProperties("ECDH", this.privateKey));
    }

    public int getAgreementSize()
    {
        return privateKey.getParameters().getCurve().getFieldElementEncodingLength();
    }

    public void calculateAgreement(CipherParameters publicKey, byte[] buf, int off)
    {
        ECDHBasicAgreement.calculateAgreementFieldElement(privateKey, (ECPublicKeyParameters)publicKey)
            .encodeTo(buf, off);
    }
}
