package org.bouncycastle.mls.crypto;

import org.bouncycastle.mls.codec.Encoder;
import org.bouncycastle.mls.codec.MLSField;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public class Secret {
    byte[] value;
    Secret[] parents;

    public Secret(byte[] value) {
        this.value = value;
        this.parents = null;
    }

    private Secret(byte[] value, Secret[] parents) {
        this.value = value;
        this.parents = parents;
    }

    public static Secret zero(CipherSuite suite) {
        return new Secret(new byte[suite.getKDF().getHashLength()]);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Secret secret = (Secret) o;
        return Arrays.equals(value, secret.value) && Arrays.equals(parents, secret.parents);
    }

    public final byte[] value() {
        return value;
    }

    public boolean isConsumed() {
        return value == null && parents == null;
    }

    public void consume() {
        if (isConsumed()) {
            return;
        }

        // Zeroize this secret
        Arrays.fill(value, (byte) 0);
        value = null;

        // Consume any linked parents
        if (parents != null) {
            for (Secret parent : parents) {
                parent.consume();
            }
            parents = null;
        }
    }

    public static Secret extract(CipherSuite suite, Secret salt, Secret ikm) {
        byte[] prk = suite.getKDF().extract(salt.value(), ikm.value());
        return new Secret(prk, new Secret[] {salt, ikm});
    }

    public Secret expand(CipherSuite suite, String label, int length) {
        byte[] labelData = label.getBytes(StandardCharsets.UTF_8);
        byte[] derivedSecret = suite.getKDF().expand(value, labelData, length);
        return new Secret(derivedSecret, new Secret[] {this});
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
        return new Secret(derivedSecret, new Secret[] {this});
    }

    public Secret deriveSecret(CipherSuite suite, String label) throws IOException, IllegalAccessException {
        return expandWithLabel(suite, label, new byte[] {}, suite.getKDF().getHashLength());
    }

    public Secret deriveTreeSecret(CipherSuite suite, String label, int generation, int length) throws IOException, IllegalAccessException {
        return expandWithLabel(suite, label, Encoder.encodeValue(generation), length);
    }
}
