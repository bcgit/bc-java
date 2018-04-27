/**
 * EdDSA-Java by str4d
 *
 * To the extent possible under law, the person who associated CC0 with
 * EdDSA-Java has waived all copyright and related or neighboring rights
 * to EdDSA-Java.
 *
 * You should have received a copy of the CC0 legalcode along with this
 * work. If not, see <https://creativecommons.org/publicdomain/zero/1.0/>.
 *
 */
package org.bouncycastle.jcajce.provider.asymmetric.rfc7748;

import org.bouncycastle.jcajce.provider.asymmetric.rfc7748.spec.RFC7748ParameterSpec;

/**
 * Common interface for all RFC7748 keys.
 * @author str4d
 */
public interface RFC7748Key {
    /**
     * The reported key algorithm for all RFC7748 keys
     */
    String KEY_ALGORITHM = "RFC7748";

    /**
     * @return a parameter specification representing the EdDSA domain
     *         parameters for the key.
     */
    RFC7748ParameterSpec getParams();
}
