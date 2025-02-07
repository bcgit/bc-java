/*
 * =============================================================================
 * 
 *   Copyright (c) 2007-2010, The JASYPT team (http://www.jasypt.org)
 * 
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 * 
 *       http://www.apache.org/licenses/LICENSE-2.0
 * 
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 * 
 * =============================================================================
 */
package org.bouncycastle.jcajce.provider.test.jasypt;



/**
 * <p>
 *  Common interface for all PBEConfig implementations that store passwords as char[] instead
 *  of String and also allow this passwords to be set as char[] instead of Strings.
 * </p>
 * 
 * @since 1.8
 * 
 * @author Daniel Fern&aacute;ndez
 * 
 */
public interface PBECleanablePasswordConfig
{

    
    /**
     * <p>
     * Return the password set, as a char array.
     * </p>
     * <p>
     * <b>Important</b>: the returned array MUST BE A COPY of the one
     * stored in the configuration object. The caller of
     * this method is therefore be responsible for cleaning this 
     * resulting char[].
     * </p>
     * 
     * @since 1.8
     * 
     */
    public char[] getPasswordCharArray();
    
    /**
     * <p>
     * Clean the password stored in this configuration object.
     * </p>
     * <p>
     * A common implementation of this <i>cleaning</i> operation consists of
     * iterating the array of chars and setting each of its positions to <tt>(char)0</tt>.
     * </p>
     * 
     * @since 1.8
     * 
     */
    public void cleanPassword();

    
}
