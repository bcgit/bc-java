package org.bouncycastle.crypto.agreement.test;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.platform.suite.api.SelectClasses;
import org.junit.runner.RunWith;

@RunWith(JUnitPlatform.class)
@SelectClasses({
    ECJPAKEParticipantTest.class,
    ECJPAKECurveTest.class,
    ECJPAKEUtilTest.class
})
public class EC_AllTests
{
    @BeforeAll
    public void setUp()
    {
        // Any setup logic before running the tests
    }

    @AfterAll
    public void tearDown()
    {
        // Any teardown logic after running the tests
    }
}