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
package org.bouncycastle.jcajce.provider.asymmetric.eddsa.math.bigint;

import java.math.BigInteger;

import org.bouncycastle.jcajce.provider.asymmetric.eddsa.math.Field;
import org.bouncycastle.jcajce.provider.asymmetric.eddsa.math.ScalarOps;

public class BigIntegerScalarOps implements ScalarOps {
    private final BigInteger l;
    private final BigIntegerLittleEndianEncoding enc;

    public BigIntegerScalarOps(Field f, BigInteger l) {
        this.l = l;
        enc = new BigIntegerLittleEndianEncoding();
        enc.setField(f);
    }

    public byte[] reduce(byte[] s) {
        return enc.encode(enc.toBigInteger(s).mod(l));
    }

    public byte[] multiplyAndAdd(byte[] a, byte[] b, byte[] c) {
        return enc.encode(enc.toBigInteger(a).multiply(enc.toBigInteger(b)).add(enc.toBigInteger(c)).mod(l));
    }

}
