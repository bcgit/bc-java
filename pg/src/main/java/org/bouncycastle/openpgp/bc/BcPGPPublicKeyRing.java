package org.bouncycastle.openpgp.bc;

import java.io.IOException;
import java.io.InputStream;

import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.operator.KeyFingerPrintCalculator;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;

public class BcPGPPublicKeyRing
    extends PGPPublicKeyRing
{
    private static KeyFingerPrintCalculator fingerPrintCalculator = new BcKeyFingerprintCalculator();

    public BcPGPPublicKeyRing(byte[] encoding)
        throws IOException
    {
        super(encoding, fingerPrintCalculator);
    }

    public BcPGPPublicKeyRing(InputStream in)
        throws IOException
    {
        super(in, fingerPrintCalculator);
    }
}
