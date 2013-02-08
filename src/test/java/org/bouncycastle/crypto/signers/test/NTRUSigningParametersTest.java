/**
 * Copyright (c) 2011 Tim Buktu (tbuktu@hotmail.com)
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

package org.bouncycastle.crypto.signers.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

import junit.framework.TestCase;
import org.bouncycastle.crypto.params.NTRUSigningKeyGenerationParameters;

public class NTRUSigningParametersTest
    extends TestCase
{

    public void testLoadSave() throws IOException {
        for (NTRUSigningKeyGenerationParameters params: new NTRUSigningKeyGenerationParameters[] {NTRUSigningKeyGenerationParameters.TEST157, NTRUSigningKeyGenerationParameters.TEST157_PROD})
            testLoadSave(params);
    }
        
    private void testLoadSave(NTRUSigningKeyGenerationParameters params) throws IOException {
        ByteArrayOutputStream os = new ByteArrayOutputStream();
        params.writeTo(os);
        ByteArrayInputStream is = new ByteArrayInputStream(os.toByteArray());
        assertEquals(params, new NTRUSigningKeyGenerationParameters(is));
    }

    public void testEqualsHashCode() throws IOException {
        for (NTRUSigningKeyGenerationParameters params: new NTRUSigningKeyGenerationParameters[] {NTRUSigningKeyGenerationParameters.TEST157, NTRUSigningKeyGenerationParameters.TEST157_PROD})
            testEqualsHashCode(params);
    }
    
    private void testEqualsHashCode(NTRUSigningKeyGenerationParameters params) throws IOException {
        ByteArrayOutputStream os = new ByteArrayOutputStream();
        params.writeTo(os);
        ByteArrayInputStream is = new ByteArrayInputStream(os.toByteArray());
        NTRUSigningKeyGenerationParameters params2 = new NTRUSigningKeyGenerationParameters(is);
        
        assertEquals(params, params2);
        assertEquals(params.hashCode(), params2.hashCode());
        
        params.N += 1;
        assertFalse(params.equals(params2));
        assertFalse(params.equals(params2));
        assertFalse(params.hashCode() == params2.hashCode());
    }

    public void testClone() {
        for (NTRUSigningKeyGenerationParameters params: new NTRUSigningKeyGenerationParameters[] {NTRUSigningKeyGenerationParameters.TEST157, NTRUSigningKeyGenerationParameters.TEST157_PROD})
            assertEquals(params, params.clone());
    }
}