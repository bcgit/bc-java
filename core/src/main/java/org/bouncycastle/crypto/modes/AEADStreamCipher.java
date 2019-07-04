package org.bouncycastle.crypto.modes;

import org.bouncycastle.crypto.StreamCipher;

public interface AEADStreamCipher extends AEADCipher {

    /**
     * return the cipher this object wraps.
     *
     * @return the cipher this object wraps.
     */
    public StreamCipher getUnderlyingCipher();

}
