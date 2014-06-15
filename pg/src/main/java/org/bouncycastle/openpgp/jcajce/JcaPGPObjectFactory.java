package org.bouncycastle.openpgp.jcajce;

import java.io.ByteArrayInputStream;
import java.io.InputStream;

import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;

/**
 * {@link PGPObjectFactory} that uses the sources cryptographic primitives from the JCA API.
 */
public class JcaPGPObjectFactory
    extends PGPObjectFactory
{
    /**
     * Construct an object factory to read PGP objects from encoded data.
     *
     * @param encoded the PGP encoded data.
     */
    public JcaPGPObjectFactory(byte[] encoded)
    {
        this(new ByteArrayInputStream(encoded));
    }

    /**
     * Construct an object factory to read PGP objects from a stream.
     *
     * @param in the stream containing PGP encoded objects.
     */
    public JcaPGPObjectFactory(InputStream in)
    {
        // FIXME: Convert this to builder style so we can set provider?
        super(in, new JcaKeyFingerprintCalculator());
    }
}
