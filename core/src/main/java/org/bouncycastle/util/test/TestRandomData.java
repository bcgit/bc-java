package org.bouncycastle.util.test;

import org.bouncycastle.util.encoders.Hex;

/**
 * A fixed secure random designed to return data for someone needing random bytes.
 */
public class TestRandomData
    extends FixedSecureRandom
{
    /**
     * Constructor from a Hex encoding of the data.
     *
     * @param encoding a Hex encoding of the data to be returned.
     */
    public TestRandomData(String encoding)
    {
        super(new Source[] { new FixedSecureRandom.Data(Hex.decode(encoding)) });
    }

    /**
     * Constructor from an array of bytes.
     *
     * @param encoding a byte array representing the data to be returned.
     */
    public TestRandomData(byte[] encoding)
    {
        super(new Source[] { new FixedSecureRandom.Data(encoding) });
    }
}
