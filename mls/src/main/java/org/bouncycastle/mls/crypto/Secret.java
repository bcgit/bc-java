package org.bouncycastle.mls.crypto;

import org.bouncycastle.mls.codec.Encoder;
import org.bouncycastle.mls.codec.MLSField;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Objects;

public class Secret {
    Secret parent;
    byte[] value;

    public Secret(byte[] valueIn) {
        parent = null;
        value = valueIn;
    }

    private Secret(Secret parentIn, byte[] valueIn) {
        parent = parentIn;
        value = valueIn;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Secret secret = (Secret) o;
        return Objects.equals(parent, secret.parent) && Arrays.equals(value, secret.value);
    }

    public final byte[] value() {
        return value;
    }

    public boolean isConsumed() {
        return value == null && parent == null;
    }

    public void consume() {
        if (isConsumed()) {
            return;
        }

        Arrays.fill(value, (byte) 0);
        value = null;
        if (parent != null) {
            parent.consume();
        }
        parent = null;
    }

    public static class KDFLabel {
        @MLSField(order=1)
        public short length;
        @MLSField(order=2)
        public byte[] label;

        @MLSField(order=3)
        public byte[] context;

        KDFLabel(short lengthIn, String labelIn, byte[] contextIn) {
            length = lengthIn;
            context = contextIn;
            label = ("MLS 1.0 " + labelIn).getBytes(StandardCharsets.UTF_8);
        }
    }

    public Secret expandWithLabel(CipherSuite suite, String label, byte[] context, int length) throws IOException, IllegalAccessException {
        KDFLabel kdfLabelStr = new KDFLabel((short) length, label, context);
        byte[] kdfLabel = Encoder.encodeValue(kdfLabelStr);
        byte[] derivedSecret = suite.getKDF().expand(value, kdfLabel, length);
        return new Secret(this, derivedSecret);
    }

    public Secret deriveSecret(CipherSuite suite, String label) throws IOException, IllegalAccessException {
        return expandWithLabel(suite, label, new byte[] {}, suite.getKDF().getHashLength());
    }

    public Secret deriveTreeSecret(CipherSuite suite, String label, int generation, int length) throws IOException, IllegalAccessException {
        return expandWithLabel(suite, label, Encoder.encodeValue(generation), length);
    }
}
