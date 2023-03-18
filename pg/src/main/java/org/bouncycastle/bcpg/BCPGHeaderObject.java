package org.bouncycastle.bcpg;

import java.io.IOException;

/**
 * Implemented by packets written as headers followed by
 * a stream of data.
 */
public interface BCPGHeaderObject
{
    /**
     * Return the header type.
     *
     * @return header type code
     */
    int getType();

    void encode(BCPGOutputStream bcpgOut)
        throws IOException;
}
