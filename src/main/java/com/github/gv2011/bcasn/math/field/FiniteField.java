package com.github.gv2011.bcasn.math.field;

import java.math.BigInteger;

public interface FiniteField
{
    BigInteger getCharacteristic();

    int getDimension();
}
