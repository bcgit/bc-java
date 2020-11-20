package org.bouncycastle.crypto.engines;

import org.bouncycastle.util.Memoable;

/**
 * Zuc256 implementation.
 * Based on https://www.is.cas.cn/ztzl2016/zouchongzhi/201801/W020180126529970733243.pdf
 */
public final class Zuc256Engine
    extends Zuc256CoreEngine
{
    /**
     * Constructor for streamCipher.
     */
    public Zuc256Engine()
    {
        super();
    }

    /**
     * Constructor for Mac.
     *
     * @param pLength the Mac length
     */
    public Zuc256Engine(final int pLength)
    {
        super(pLength);
    }

    /**
     * Constructor for Memoable.
     *
     * @param pSource the source engine
     */
    private Zuc256Engine(final Zuc256Engine pSource)
    {
        super(pSource);
    }

    /**
     * Create a copy of the engine.
     *
     * @return the copy
     */
    public Memoable copy()
    {
        return new Zuc256Engine(this);
    }
}
