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
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.NTRUSigningKeyPairGenerator;
import org.bouncycastle.crypto.params.NTRUSigningKeyGenerationParameters;
import org.bouncycastle.crypto.params.NTRUSigningPrivateKeyParameters;
import org.bouncycastle.crypto.params.NTRUSigningPublicKeyParameters;
import org.bouncycastle.crypto.signers.NTRUSigner;

public class NTRUSignatureKeyTest
    extends TestCase
{
    public void testEncode() throws IOException {
        for (NTRUSigningKeyGenerationParameters params: new NTRUSigningKeyGenerationParameters[] {NTRUSigningKeyGenerationParameters.TEST157, NTRUSigningKeyGenerationParameters.TEST157_PROD})
            testEncode(params);
    }
    
    private void testEncode(NTRUSigningKeyGenerationParameters params) throws IOException {
        NTRUSigner ntru = new NTRUSigner(params.getSigningParameters());
        NTRUSigningKeyPairGenerator kGen = new NTRUSigningKeyPairGenerator();

        kGen.init(params);

        AsymmetricCipherKeyPair kp = kGen.generateKeyPair();
        
        NTRUSigningPrivateKeyParameters kPriv = (NTRUSigningPrivateKeyParameters)kp.getPrivate();
        NTRUSigningPublicKeyParameters kPub = (NTRUSigningPublicKeyParameters)kp.getPublic();
                
        // encode to byte[] and reconstruct
        byte[] priv = kPriv.getEncoded();
        byte[] pub = kPub.getEncoded();
        AsymmetricCipherKeyPair kp2 = new AsymmetricCipherKeyPair(new NTRUSigningPublicKeyParameters(pub, params.getSigningParameters()), new NTRUSigningPrivateKeyParameters(priv, params));
        assertEquals(kPub, kp2.getPublic());
        assertEquals(kPriv, kp2.getPrivate());
        
        // encode to OutputStream and reconstruct
        ByteArrayOutputStream bos1 = new ByteArrayOutputStream();
        ByteArrayOutputStream bos2 = new ByteArrayOutputStream();
        kPriv.writeTo(bos1);
        kPub.writeTo(bos2);
        ByteArrayInputStream bis1 = new ByteArrayInputStream(bos1.toByteArray());
        ByteArrayInputStream bis2 = new ByteArrayInputStream(bos2.toByteArray());
        AsymmetricCipherKeyPair kp3 = new AsymmetricCipherKeyPair(new NTRUSigningPublicKeyParameters(bis2, params.getSigningParameters()), new NTRUSigningPrivateKeyParameters(bis1, params));
        assertEquals(kPub, kp3.getPublic());
        assertEquals(kPriv, kp3.getPrivate());
    }
}