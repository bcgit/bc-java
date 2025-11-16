package org.bouncycastle.crypto.hash2curve.test;


import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Test vector data
 */
public class TestVectorData {

    private String L;
    private String Z;
    private String ciphersuite;
    private String curve;
    private String dst;
    private String expand;
    private Field field;
    private String hash;
    private String k;
    private Map<String, String> map;
    private boolean randomOracle;
    private List<Vector> vectors;

    private TestVectorData() {
        this.map = new HashMap<>();
        this.vectors = new ArrayList<>();
    }

    public static Builder builder() {
        return new Builder();
    }

    public String getCiphersuite() {
        return ciphersuite;
    }

    public String getCurve() {
        return curve;
    }

    public String getDst() {
        return dst;
    }

    public String getExpand() {
        return expand;
    }

    public Field getField() {
        return field;
    }

    public String getHash() {
        return hash;
    }

    public String getK() {
        return k;
    }

    public String getL() {
        return L;
    }

    public Map<String, String> getMap() {
        return map;
    }

    public boolean isRandomOracle() {
        return randomOracle;
    }

    public List<Vector> getVectors() {
        return vectors;
    }

    public String getZ() {
        return Z;
    }

    public static class Builder {
        private final TestVectorData data;

        private Builder() {
            this.data = new TestVectorData();
        }
        public Builder L(final String L) {
            this.data.L = L;
            return this;
        }
        public Builder Z(final String Z) {
            this.data.Z = Z;
            return this;
        }
        public Builder ciphersuite(final String ciphersuite) {
            this.data.ciphersuite = ciphersuite;
            return this;
        }
        public Builder curve(final String curve) {
            this.data.curve = curve;
            return this;
        }
        public Builder dst(final String dst) {
            this.data.dst = dst;
            return this;
        }
        public Builder expand(final String expand) {
            this.data.expand = expand;
            return this;
        }
        public Builder field(final String m, final String p) {
            this.data.field = new Field(m, p);
            return this;
        }
        public Builder hash(final String hash) {
            this.data.hash = hash;
            return this;
        }
        public Builder k(final String k) {
            this.data.k = k;
            return this;
        }
        public Builder addMap(final String key, final String value) {
            this.data.map.put(key, value);
            return this;
        }
        public Builder randomOracle(final boolean randomOracle) {
            this.data.randomOracle = randomOracle;
            return this;
        }
        public Builder addVector(final Vector vector) {
            this.data.vectors.add(vector);
            return this;
        }
        public TestVectorData build() {
            return this.data;
        }
    }

    public static class Field {
        public Field(final String m, final String p) {
            this.m = m;
            this.p = p;
        }

        private String m;
        private String p;

        public String getM() {
            return m;
        }

        public String getP() {
            return p;
        }
    }

    public static class Vector {
        private Vector() {
            this.P = new HashMap<>();
            this.Q0 = new HashMap<>();
            this.Q1 = new HashMap<>();
            this.u = new ArrayList<>();
        }

        private Map<String, String> P;
        private Map<String, String> Q0;
        private Map<String, String> Q1;
        private String msg;
        private List<String> u;

        public static Builder builder() {
            return new Builder();
        }

        public String getMsg() {
            return msg;
        }

        public Map<String, String> getP() {
            return P;
        }

        public Map<String, String> getQ0() {
            return Q0;
        }

        public Map<String, String> getQ1() {
            return Q1;
        }

        public List<String> getU() {
            return u;
        }

        public static class Builder{
            private final Vector vector;

            private Builder() {
                this.vector = new Vector();
            }

            public Builder msg(final String msg) {
                this.vector.msg = msg;
                return this;
            }

            public Builder addU(final String u) {
                this.vector.u.add(u);
                return this;
            }
            public Builder addP(final String key, final String value) {
                this.vector.P.put(key, value);
                return this;
            }
            public Builder addQ0(final String key, final String value) {
                this.vector.Q0.put(key, value);
                return this;
            }

            public Builder addQ1(final String key, final String value) {
                this.vector.Q1.put(key, value);
                return this;
            }

            public Vector build() {
                return this.vector;
            }
        }

    }
}
