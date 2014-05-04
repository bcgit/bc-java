package org.bouncycastle.openpgp.jcajce;

import java.io.IOException;
import java.io.InputStream;

import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.operator.KeyFingerPrintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;

public class JcaPGPPublicKeyRing
    extends PGPPublicKeyRing
{
    private static KeyFingerPrintCalculator fingerPrintCalculator = new JcaKeyFingerprintCalculator();

    public JcaPGPPublicKeyRing(byte[] encoding)
        throws IOException
    {
        super(encoding, fingerPrintCalculator);
    }

    public JcaPGPPublicKeyRing(InputStream in)
        throws IOException
    {
        super(in, fingerPrintCalculator);
    }
}
