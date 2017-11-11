package com.github.gv2011.asn1.util.test;

/*-
 * %---license-start---
 * Vinz ASN.1
 * %
 * Copyright (C) 2016 - 2017 Vinz (https://github.com/gv2011)
 * %
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
 * %---license-end---
 */
import com.github.gv2011.asn1.util.Strings;

public class SimpleTestResult implements TestResult
{
    private static final String SEPARATOR = Strings.lineSeparator();

    private final boolean             success;
    private final String              message;
    private Throwable           exception;

    public SimpleTestResult(final boolean success, final String message)
    {
        this.success = success;
        this.message = message;
    }

    public SimpleTestResult(final boolean success, final String message, final Throwable exception)
    {
        this.success = success;
        this.message = message;
        this.exception = exception;
    }

    public static TestResult successful(
        final LegacyTest test,
        final String message)
    {
        return new SimpleTestResult(true, test.getName() + ": " + message);
    }

    public static TestResult failed(
        final LegacyTest test,
        final String message)
    {
        return new SimpleTestResult(false, test.getName() + ": " + message);
    }

    public static TestResult failed(
        final LegacyTest test,
        final String message,
        final Throwable t)
    {
        return new SimpleTestResult(false, test.getName() + ": " + message, t);
    }

    public static TestResult failed(
        final LegacyTest test,
        final String message,
        final Object expected,
        final Object found)
    {
        return failed(test, message + SEPARATOR + "Expected: " + expected + SEPARATOR + "Found   : " + found);
    }

    public static String failedMessage(final String algorithm, final String testName, final String expected,
            final String actual)
    {
        final StringBuffer sb = new StringBuffer(algorithm);
        sb.append(" failing ").append(testName);
        sb.append(SEPARATOR).append("    expected: ").append(expected);
        sb.append(SEPARATOR).append("    got     : ").append(actual);

        return sb.toString();
    }

    @Override
    public boolean isSuccessful()
    {
        return success;
    }

    @Override
    public String toString()
    {
        return message;
    }

    @Override
    public Throwable getException()
    {
        return exception;
    }
}
