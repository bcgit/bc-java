package org.bouncycastle.crypto.agreement;

import java.math.BigInteger;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.params.CombinedPrivateParameters;
import org.bouncycastle.crypto.params.CombinedPublicParameters;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;

/**
 * FFC static/ephemeral agreement as described in NIST SP 800-56A.
 */
public class CombinedAgreement
{
    private CombinedPrivateParameters privParams;

    public void init(
        CipherParameters key)
    {
        this.privParams = (CombinedPrivateParameters)key;
    }

    public int getFieldSize()
    {
        return (privParams.getStaticPrivateKey().getParameters().getP().bitLength() + 7) / 8;
    }

    public byte[] calculateAgreement(CipherParameters pubKey)
    {
        CombinedPublicParameters pubParams = (CombinedPublicParameters)pubKey;

        DHBasicAgreement sAgree = new DHBasicAgreement();
        DHBasicAgreement eAgree = new DHBasicAgreement();

        sAgree.init(privParams.getStaticPrivateKey());

        BigInteger sComp = sAgree.calculateAgreement(pubParams.getStaticPublicKey());

        eAgree.init(privParams.getEphemeralPrivateKey());

        BigInteger eComp = eAgree.calculateAgreement(pubParams.getEphemeralPublicKey());

        return Arrays.concatenate(
            BigIntegers.asUnsignedByteArray(this.getFieldSize(), eComp),
            BigIntegers.asUnsignedByteArray(this.getFieldSize(), sComp));
    }
}
