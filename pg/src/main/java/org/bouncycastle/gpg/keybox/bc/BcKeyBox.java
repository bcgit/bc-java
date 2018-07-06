package org.bouncycastle.gpg.keybox.bc;

import java.io.IOException;
import java.io.InputStream;

import org.bouncycastle.gpg.keybox.KeyBox;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;

public class BcKeyBox
    extends KeyBox
{
    public BcKeyBox(byte[] encoding)
        throws IOException
    {
        super(encoding, new BcKeyFingerprintCalculator(), new BcBlobVerifier());
    }

    public BcKeyBox(InputStream input)
        throws IOException
    {
        super(input, new BcKeyFingerprintCalculator(), new BcBlobVerifier());
    }
}
