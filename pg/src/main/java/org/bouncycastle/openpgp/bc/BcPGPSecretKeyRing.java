package org.bouncycastle.openpgp.bc;

import java.io.IOException;
import java.io.InputStream;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.operator.KeyFingerPrintCalculator;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;

public class BcPGPSecretKeyRing
    extends PGPSecretKeyRing
{
    private static KeyFingerPrintCalculator fingerPrintCalculator = new BcKeyFingerprintCalculator();

    public BcPGPSecretKeyRing(byte[] encoding)
        throws IOException, PGPException
    {
        super(encoding, fingerPrintCalculator);
    }

    public BcPGPSecretKeyRing(InputStream in)
        throws IOException, PGPException
    {
        super(in, fingerPrintCalculator);
    }
}
