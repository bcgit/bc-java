package com.github.gv2011.asn1.util.test;

/*-
 * #%L
 * Vinz ASN.1
 * %%
 * Copyright (C) 2016 - 2017 Vinz (https://github.com/gv2011)
 * %%
 * Please note this should be read in the same way as the MIT license. (https://www.bouncycastle.org/licence.html)
 * 
 * Copyright (c) 2000-2015 The Legion of the Bouncy Castle Inc. (http://www.bouncycastle.org)
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this software 
 * and associated documentation files (the "Software"), to deal in the Software without restriction, 
 * including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, 
 * and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all copies or substantial
 * portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
 * INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
 * PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 * LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
 * OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 * #L%
 */


import java.io.PrintStream;

import com.github.gv2011.asn1.util.Arrays;

public abstract class SimpleTest
    implements LegacyTest
{
    @Override
    public abstract String getName();

    private TestResult success()
    {
        return SimpleTestResult.successful(this, "Okay");
    }
    
    protected void fail(
        String message)
    {
        throw new TestFailedException(SimpleTestResult.failed(this, message));
    }
    
    protected void fail(
        String    message,
        Throwable throwable)
    {
        throw new TestFailedException(SimpleTestResult.failed(this, message, throwable));
    }
    
    protected void fail(
        String message,
        Object expected,
        Object found)
    {
        throw new TestFailedException(SimpleTestResult.failed(this, message, expected, found));
    }
        
    protected boolean areEqual(
        byte[] a,
        byte[] b)
    {
        return Arrays.areEqual(a, b);
    }
    
    @Override
    public TestResult perform()
    {
        try
        {
            performTest();
            
            return success();
        }
        catch (TestFailedException e)
        {
            return e.getResult();
        }
        catch (Exception e)
        {
            return SimpleTestResult.failed(this, "Exception: " +  e, e);
        }
    }
    
    protected static void runTest(
        LegacyTest        test)
    {
        runTest(test, System.out);
    }
    
    protected static void runTest(
        LegacyTest        test,
        PrintStream out)
    {
        TestResult      result = test.perform();

        out.println(result.toString());
        if (result.getException() != null)
        {
            result.getException().printStackTrace(out);
        }
    }

    public abstract void performTest()
        throws Exception;
}
