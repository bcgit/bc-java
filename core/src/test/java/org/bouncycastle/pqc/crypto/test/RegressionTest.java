package org.bouncycastle.pqc.crypto.test;

import org.bouncycastle.util.test.SimpleTest;
import org.bouncycastle.util.test.Test;

public class RegressionTest
{
    public static Test[]    tests = {
        new Sphincs256Test(),
        new NewHopeTest()
    };

    public static void main(String[] args)
    {
        SimpleTest.runTests(tests);
    }
}
