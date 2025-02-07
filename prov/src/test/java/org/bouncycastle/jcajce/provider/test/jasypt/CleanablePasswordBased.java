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
 * Common interface for all entities which can be set a password in char[] shape,
 * which can be cleaned once the encryptor is initialized so that no immutable
 * Strings containing the password are left in memory.
 * </p>
 * 
 * @since 1.8
 * 
 * @author Daniel Fern&aacute;ndez
 * 
 */
public interface CleanablePasswordBased
    extends PasswordBased {
    
    /**
     * <p>
     * Sets a password to be used by the encryptor, as a (cleanable) char[].
     * </p>
     * 
     * @since 1.8
     * 
     * @param password the password to be used.
     */
    public void setPasswordCharArray(char[] password);

}
