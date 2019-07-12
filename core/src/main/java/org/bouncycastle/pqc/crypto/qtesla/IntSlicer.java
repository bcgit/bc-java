package org.bouncycastle.pqc.crypto.qtesla;

/**
 * Simulates pointer arithmetic.
 * A utility for porting C to Java where C code makes heavy use of pointer arithmetic.
 *
 * @Deprecated Remove when Post-Quantum Standardization project has finished and standard is published.
 */
final class IntSlicer
{
    private final int[] values;
    private int base;

    IntSlicer(int[] values, int base)
    {
        this.values = values;
        this.base = base;
    }

    final int at(int index)
    {
        return values[base + index];
    }

    final int at(int index, int value)
    {
        return values[base + index] = value;
    }


    final int at(int index, long value)
    {
        return values[base + index] = (int)value;
    }

    final IntSlicer from(int o)
    {
        return new IntSlicer(values, base + o);
    }

    final void incBase(int paramM)
    {
        base += paramM;

    }

    final IntSlicer copy()
    {
        return new IntSlicer(values, base);
    }

}
