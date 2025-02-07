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
 * Marker interface for all implementations of {@link SaltGenerator} that
 * will always return the same salt (for the same amount of bytes asked).
 * </p>
 * <p>
 * Use of this interface in salt generators enables encryptors to perform
 * some performance optimizations whenever they are used.
 * </p>
 * 
 * @since 1.9.2
 * 
 * @author Daniel Fern&aacute;ndez
 * 
 */
public interface FixedSaltGenerator
    extends SaltGenerator {

    // Marker interface - no methods added
    
}
