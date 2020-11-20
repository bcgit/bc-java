package org.bouncycastle.crypto.engines;

import org.bouncycastle.util.Memoable;

/**
 * Zuc256 implementation.
 * Based on https://www.is.cas.cn/ztzl2016/zouchongzhi/201801/W020180126529970733243.pdf
 */
public final class Zuc128Engine
    extends Zuc128CoreEngine
{
    /**
     * Constructor for streamCipher.
     */
    public Zuc128Engine()
    {
        super();
    }

    /**
     * Constructor for Memoable.
     *
     * @param pSource the source engine
     */
    private Zuc128Engine(final Zuc128Engine pSource)
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
        return new Zuc128Engine(this);
    }
}
