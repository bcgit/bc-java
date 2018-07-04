package org.bouncycastle.math.ec;

public interface PreCompCallback
{
    PreCompInfo precompute(PreCompInfo existing);
}
