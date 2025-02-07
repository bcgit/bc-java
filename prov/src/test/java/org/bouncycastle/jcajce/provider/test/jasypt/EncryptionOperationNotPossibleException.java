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
 * General exception thrown when any errors are raised during encryption,
 * digesting, etc.
 * </p>
 * <p>
 * It is intended to provide very little information (if any) of the error
 * causes, so that encryption internals are not revealed through error
 * messages.
 * </p>
 * 
 * @since 1.0
 * 
 * @author Daniel Fern&aacute;ndez
 * 
 */
public final class EncryptionOperationNotPossibleException
    extends RuntimeException {

    private static final long serialVersionUID = 6304674109588715145L;

    public EncryptionOperationNotPossibleException() {
        super();
    }

    public EncryptionOperationNotPossibleException(final Throwable t) {
        super(t);
    }
    
    public EncryptionOperationNotPossibleException(final String message) {
        super(message);
    }
    
}
