package org.bouncycastle.crypto.agreement;

import java.math.BigInteger;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.params.ECDHEPrivateParameters;
import org.bouncycastle.crypto.params.ECDHEPublicParameters;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;

/**
 * EC static/ephemeral agreement as described in NIST SP 800-56A using EC co-factor Diffie-Hellman.
 */
public class ECDHCEphemeralAgreement
{
    private ECDHEPrivateParameters privParams;

    public void init(
        CipherParameters key)
    {
        this.privParams = (ECDHEPrivateParameters)key;
    }

    public int getFieldSize()
    {
        return (privParams.getStaticPrivateKey().getParameters().getCurve().getFieldSize() + 7) / 8;
    }

    public byte[] calculateAgreement(CipherParameters pubKey)
    {
        ECDHEPublicParameters pubParams = (ECDHEPublicParameters)pubKey;

        ECDHCBasicAgreement sAgree = new ECDHCBasicAgreement();
        ECDHCBasicAgreement eAgree = new ECDHCBasicAgreement();

        sAgree.init(privParams.getStaticPrivateKey());

        BigInteger sComp = sAgree.calculateAgreement(pubParams.getStaticPublicKey());

        eAgree.init(privParams.getEphemeralPrivateKey());

        BigInteger eComp = eAgree.calculateAgreement(pubParams.getEphemeralPublicKey());

        return Arrays.concatenate(
            BigIntegers.asUnsignedByteArray(this.getFieldSize(), eComp),
            BigIntegers.asUnsignedByteArray(this.getFieldSize(), sComp));
    }
}
