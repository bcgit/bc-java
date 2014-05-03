package org.bouncycastle.openpgp.jcajce;

import java.io.ByteArrayInputStream;
import java.io.InputStream;

import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;

public class JcaPGPObjectFactory
    extends PGPObjectFactory
{
    public JcaPGPObjectFactory(byte[] encoding)
    {
        this(new ByteArrayInputStream(encoding));
    }

    public JcaPGPObjectFactory(InputStream in)
    {
        super(in, new JcaKeyFingerprintCalculator());
    }
}
