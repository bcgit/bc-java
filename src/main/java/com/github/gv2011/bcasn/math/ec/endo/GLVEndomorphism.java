package com.github.gv2011.bcasn.math.ec.endo;

import java.math.BigInteger;

public interface GLVEndomorphism extends ECEndomorphism
{
    BigInteger[] decomposeScalar(BigInteger k);
}
