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
package org.bouncycastle.jcajce.provider.asymmetric.rfc7748.spec;

import java.security.spec.AlgorithmParameterSpec;

/**
 * Implementation of AlgorithmParameterSpec that holds the name of a named
 * RFC7748 curve specification.
 * @author str4d
 *
 */
public class RFC7748GenParameterSpec implements AlgorithmParameterSpec {
    private final String name;

    public RFC7748GenParameterSpec(String stdName) {
        name = stdName;
    }

    public String getName() {
        return name;
    }
}
