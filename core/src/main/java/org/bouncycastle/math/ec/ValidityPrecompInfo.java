package org.bouncycastle.math.ec;

class ValidityPrecompInfo implements PreCompInfo
{
    static final String PRECOMP_NAME = "bc_validity";

    private boolean failed = false;
    private boolean curveEquationPassed = false;
    private boolean orderPassed = false;

    boolean hasFailed()
    {
        return failed;
    }

    void reportFailed()
    {
        failed = true;
    }

    boolean hasCurveEquationPassed()
    {
        return curveEquationPassed;
    }

    void reportCurveEquationPassed()
    {
        curveEquationPassed = true;
    }

    boolean hasOrderPassed()
    {
        return orderPassed;
    }

    void reportOrderPassed()
    {
        orderPassed = true;
    }
}
