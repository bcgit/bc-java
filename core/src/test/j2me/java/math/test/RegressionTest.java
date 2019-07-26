package java.math.test;

import org.bouncycastle.util.test.SimpleTest;
import org.bouncycastle.util.test.Test;

public class RegressionTest
{
    public static Test[]    tests = {
        new BigIntegerTest()
    };

    public static void main(String[] args)
    {
        SimpleTest.runTests(tests);
    }
}
