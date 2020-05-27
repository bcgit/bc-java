package org.bouncycastle.openpgp.jcajce;

import java.io.IOException;
import java.io.InputStream;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.operator.KeyFingerPrintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;

public class JcaPGPSecretKeyRing
    extends PGPSecretKeyRing
{
    private static KeyFingerPrintCalculator getFingerPrintCalculator()
    {
        return new JcaKeyFingerprintCalculator();
    }

    public JcaPGPSecretKeyRing(byte[] encoding)
        throws IOException, PGPException
    {
        super(encoding, getFingerPrintCalculator());
    }

    public JcaPGPSecretKeyRing(InputStream in)
        throws IOException, PGPException
    {
        super(in, getFingerPrintCalculator());
    }
}
