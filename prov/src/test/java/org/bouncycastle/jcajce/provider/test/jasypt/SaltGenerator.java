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
 * Common interface for all salt generators which can be applied in digest
 * or encryption operations.
 * </p>
 * <p>
 * <b>Every implementation of this interface must be thread-safe</b>.
 * </p>
 * 
 * @since 1.2
 * 
 * @author Daniel Fern&aacute;ndez
 * 
 */
public interface SaltGenerator
{

    /**
     * <p>
     * This method will be called for requesting the generation of a new
     * salt of the specified length.
     * </p>
     * 
     * @param lengthBytes the requested length for the salt. 
     * @return the generated salt.
     */
    public byte[] generateSalt(int lengthBytes);
    
    
    /**
     * <p>
     * Determines if the digests and encrypted messages created with a 
     * specific salt generator will include (prepended) the unencrypted 
     * salt itself, so that it can be used for matching and decryption 
     * operations.
     * </p>
     * <p>
     * Generally, including the salt unencrypted in encryption results will 
     * be mandatory for randomly generated salts, or for those generated in a 
     * non-predictable manner.
     * Otherwise, digest matching and decryption operations will always fail.
     * For fixed salts, inclusion will be optional (and in fact undesirable 
     * if we want to hide the salt value).
     * </p>    
     * 
     * @return whether the plain (unencrypted) salt has to be included in 
     *         encryption results or not.
     */
    public boolean includePlainSaltInEncryptionResults();

    
}
