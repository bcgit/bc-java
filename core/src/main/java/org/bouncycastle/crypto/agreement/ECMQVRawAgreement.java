package org.bouncycastle.crypto.agreement;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.RawAgreement;
import org.bouncycastle.crypto.params.MQVPrivateParameters;
import org.bouncycastle.crypto.params.MQVPublicParameters;

public final class ECMQVRawAgreement
    implements RawAgreement
{
    private MQVPrivateParameters privateParams;

    public void init(CipherParameters parameters)
    {
        this.privateParams = (MQVPrivateParameters)parameters;

        CryptoServicesRegistrar.checkConstraints(
            Utils.getDefaultProperties("ECMQV", this.privateParams.getStaticPrivateKey()));
    }

    public int getAgreementSize()
    {
        return privateParams.getStaticPrivateKey().getParameters().getCurve().getFieldElementEncodingLength();
    }

    public void calculateAgreement(CipherParameters publicKey, byte[] buf, int off)
    {
        ECMQVBasicAgreement.calculateAgreementFieldElement(privateParams, (MQVPublicParameters)publicKey)
            .encodeTo(buf, off);
    }
}
