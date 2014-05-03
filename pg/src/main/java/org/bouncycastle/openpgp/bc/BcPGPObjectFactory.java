package org.bouncycastle.openpgp.bc;

import java.io.ByteArrayInputStream;
import java.io.InputStream;

import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;

public class BcPGPObjectFactory
    extends PGPObjectFactory
{
    public BcPGPObjectFactory(byte[] encoding)
    {
        this(new ByteArrayInputStream(encoding));
    }

    public BcPGPObjectFactory(InputStream in)
    {
        super(in, new BcKeyFingerprintCalculator());
    }
}
