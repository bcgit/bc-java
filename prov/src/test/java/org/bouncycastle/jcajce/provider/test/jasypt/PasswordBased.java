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
 * Common interface for all entities which can be set a password.
 * </p>
 * 
 * @since 1.3
 * 
 * @author Daniel Fern&aacute;ndez
 * 
 */
public interface PasswordBased
{
    
    /**
     * <p>
     * Sets a password to be used by the encryptor.
     * </p>
     * 
     * @param password the password to be used.
     */
    public void setPassword(String password);

}
