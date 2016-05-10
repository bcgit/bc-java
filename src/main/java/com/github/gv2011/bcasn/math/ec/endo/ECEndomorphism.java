package com.github.gv2011.bcasn.math.ec.endo;

import com.github.gv2011.bcasn.math.ec.ECPointMap;

public interface ECEndomorphism
{
    ECPointMap getPointMap();

    boolean hasEfficientPointMap();
}
