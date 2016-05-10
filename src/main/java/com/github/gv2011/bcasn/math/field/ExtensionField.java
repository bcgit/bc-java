package com.github.gv2011.bcasn.math.field;

public interface ExtensionField extends FiniteField
{
    FiniteField getSubfield();

    int getDegree();
}
