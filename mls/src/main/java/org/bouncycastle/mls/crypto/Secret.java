package org.bouncycastle.mls.crypto;

import org.bouncycastle.mls.codec.Encoder;
import org.bouncycastle.mls.codec.MLSField;

import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

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
        static final Charset charset = StandardCharsets.UTF_8;

        @MLSField(order=1)
        public short length;
        @MLSField(order=2)
        public byte[] label;

        @MLSField(order=3)
        public byte[] context;

        KDFLabel(short lengthIn, String labelIn, byte[] contextIn) {
            length = lengthIn;
            context = contextIn;
            label = ("MLS 1.0 " + labelIn).getBytes(charset);
        }
    }

    public Secret expandWithLabel(CipherSuite suite, String label, byte[] context, int length) throws IOException, IllegalAccessException {
        KDFLabel kdfLabelStr = new KDFLabel((short) length, label, context);
        byte[] kdfLabel = Encoder.encodeValue(kdfLabelStr);
        byte[] derivedSecret = suite.getKDF().expand(value, kdfLabel, length);
        return new Secret(this, derivedSecret);
    }

    public Secret deriveSecret(CipherSuite suite, String label) throws IOException, IllegalAccessException {
        return expandWithLabel(suite, label, new byte[] {}, suite.getKDF().hashLength());
    }
}
