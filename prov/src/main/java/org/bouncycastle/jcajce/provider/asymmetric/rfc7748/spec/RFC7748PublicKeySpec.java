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

import java.security.spec.KeySpec;

import org.bouncycastle.jcajce.provider.asymmetric.rfc7748.math.GroupElement;

/**
 * @author str4d
 *
 */
public class RFC7748PublicKeySpec implements KeySpec {
    private final GroupElement A;
    private final GroupElement Aneg;
    private final RFC7748ParameterSpec spec;

    /**
     * @param pk the public key
     * @param spec the parameter specification for this key
     * @throws IllegalArgumentException if key length is wrong
     */
    public RFC7748PublicKeySpec(byte[] pk, RFC7748ParameterSpec spec) {
        if (pk.length != spec.getCurve().getField().getb()/8)
            throw new IllegalArgumentException("public-key length is wrong");

        this.A = new GroupElement(spec.getCurve(), pk);
        // Precompute -A for use in verification.
        this.Aneg = A.negate();
        Aneg.precompute(false);
        this.spec = spec;
    }

    public RFC7748PublicKeySpec(GroupElement A, RFC7748ParameterSpec spec) {
        this.A = A;
        this.Aneg = A.negate();
        Aneg.precompute(false);
        this.spec = spec;
    }

    public GroupElement getA() {
        return A;
    }

    public GroupElement getNegativeA() {
        return Aneg;
    }

    public RFC7748ParameterSpec getParams() {
        return spec;
    }
}
