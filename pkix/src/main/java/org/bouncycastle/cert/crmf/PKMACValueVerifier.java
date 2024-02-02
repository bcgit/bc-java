package org.bouncycastle.cert.crmf;

import org.bouncycastle.asn1.cmp.PBMParameter;
import org.bouncycastle.asn1.crmf.PKMACValue;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.operator.MacCalculator;
import org.bouncycastle.util.Arrays;

class PKMACValueVerifier
{
    private final PKMACBuilder builder;

    public PKMACValueVerifier(PKMACBuilder builder)
    {
        this.builder = builder;
    }

    public boolean isValid(PKMACValue value, char[] password, SubjectPublicKeyInfo keyInfo)
        throws CRMFException
    {
        builder.setParameters(PBMParameter.getInstance(value.getAlgId().getParameters()));

        MacCalculator calculator = CRMFUtil.getMacCalculator(builder, password, keyInfo);

        return Arrays.constantTimeAreEqual(calculator.getMac(), value.getValue().getOctets());
    }
}
