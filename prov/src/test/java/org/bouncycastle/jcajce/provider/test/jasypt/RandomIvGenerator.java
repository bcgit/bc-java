/*
 * =============================================================================
 * 
 *   Copyright (c) 2019, The JASYPT team (http://www.jasypt.org)
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

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/**
 * <p>
 * This implementation of {@link IvGenerator} holds a <b>secure</b> random
 * generator which can be used for generating random initialization vectors (IV) for encryption.
 * </p>
 * <p>
 * The algorithm used for random number generation can be configured at 
 * instantiation time. If not, the default algorithm will be used.
 * </p>
 * <p>
 * This class is <i>thread-safe</i>.
 * </p>
 * 
 * @since 1.9.3
 * 
 * @author Hoki Torres
 * 
 */
public class RandomIvGenerator
    implements IvGenerator {

    /**
     * The default algorithm to be used for secure random number
     * generation: set to SHA1PRNG.
     */
    public static final String DEFAULT_SECURE_RANDOM_ALGORITHM = "SHA1PRNG";

    private final SecureRandom random;


    /**
     * Creates a new instance of <tt>RandomIvGenerator</tt> using the
     * default secure random number generation algorithm.
     */
    public RandomIvGenerator() {
        this(DEFAULT_SECURE_RANDOM_ALGORITHM);
    }


    /**
     * Creates a new instance of <tt>RandomIvGenerator</tt> specifying a
     * secure random number generation algorithm.
     */
    public RandomIvGenerator(final String secureRandomAlgorithm) {
        super();
        try {
            this.random = SecureRandom.getInstance(secureRandomAlgorithm);
        } catch (NoSuchAlgorithmException e) {
            throw new EncryptionInitializationException(e);
        }
    }
    

    /**
     * Generate a random IV of the specified length in bytes.
     * 
     * @param lengthBytes length in bytes.
     * @return the generated IV.
     */
    public byte[] generateIv(final int lengthBytes) {
        final byte[] iv = new byte[lengthBytes];
        synchronized (this.random) {
            this.random.nextBytes(iv);
        }
        return iv;
    }


    /**
     * This IV generator needs the IV to be included unencrypted in
     * encryption results, because of its being random. This method will always 
     * return true.
     * 
     * @return true
     */
    public boolean includePlainIvInEncryptionResults() {
        return true;
    }

    
}
