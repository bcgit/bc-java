package org.bouncycastle.openpgp.bc;

import java.io.ByteArrayInputStream;
import java.io.InputStream;

import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;

/**
 * {@link PGPObjectFactory} that uses the Bouncy Castle lightweight API to implement cryptographic
 * primitives.
 */
public class BcPGPObjectFactory
    extends PGPObjectFactory
{
    /**
     * Construct an object factory to read PGP objects from encoded data.
     * 
     * @param encoded the PGP encoded data.
     */
    public BcPGPObjectFactory(byte[] encoded)
    {
        this(new ByteArrayInputStream(encoded));
    }

    /**
     * Construct an object factory to read PGP objects from a stream.
     *
     * @param in the stream containing PGP encoded objects.
     */
    public BcPGPObjectFactory(InputStream in)
    {
        super(in, new BcKeyFingerprintCalculator());
    }
}
