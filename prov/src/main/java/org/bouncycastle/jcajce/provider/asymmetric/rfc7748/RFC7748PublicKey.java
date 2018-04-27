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

import java.io.IOException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jcajce.provider.asymmetric.rfc7748.math.GroupElement;
import org.bouncycastle.jcajce.provider.asymmetric.rfc7748.spec.RFC7748NamedCurveTable;
import org.bouncycastle.jcajce.provider.asymmetric.rfc7748.spec.RFC7748ParameterSpec;
import org.bouncycastle.jcajce.provider.asymmetric.rfc7748.spec.RFC7748PublicKeySpec;

/**
 * An EdDSA public key.
 *<p>
 * Warning: Public key encoding is is based on the current curdle WG draft,
 * and is subject to change. See getEncoded().
 *</p><p>
 * For compatibility with older releases, decoding supports both the old and new
 * draft specifications. See decode().
 *</p><p>
 * Ref: https://tools.ietf.org/html/draft-ietf-curdle-pkix-04
 *</p><p>
 * Old Ref: https://tools.ietf.org/html/draft-josefsson-pkix-eddsa-04
 *</p>
 * @author str4d
 *
 */
public class RFC7748PublicKey implements RFC7748Key, PublicKey {
    private static final long serialVersionUID = 9837459837498475L;
    private final GroupElement A;
    private final GroupElement Aneg;
    private final byte[] Abyte;
    private final RFC7748ParameterSpec paramSpec;

    // OID 1.3.101.xxx
    private static final int OID_OLD = 100;
    private static final int OID_ED25519 = 112;
    private static final int OID_BYTE = 8;
    private static final int IDLEN_BYTE = 3;

    public RFC7748PublicKey(RFC7748PublicKeySpec spec) {
        this.A = spec.getA();
        this.Aneg = spec.getNegativeA();
        this.Abyte = this.A.toByteArray();
        this.paramSpec = spec.getParams();
    }

    public RFC7748PublicKey(X509EncodedKeySpec spec) throws InvalidKeySpecException {
        this(new RFC7748PublicKeySpec(decode(spec.getEncoded()),
                                    RFC7748NamedCurveTable.getByName("Ed25519")));
    }

    public RFC7748PublicKey(SubjectPublicKeyInfo keyInfo, String curveName) throws InvalidKeySpecException, IOException {
        this(new RFC7748PublicKeySpec(decode(keyInfo.getEncoded()),
                                    RFC7748NamedCurveTable.getByName(curveName)));
    }

    @Override
    public String getAlgorithm() {
        return KEY_ALGORITHM;
    }

    @Override
    public String getFormat() {
        return "X.509";
    }

    /**
     * Returns the public key in its canonical encoding.
     *<p>
     * This implements the following specs:
     *<ul><li>
     * General encoding: https://tools.ietf.org/html/draft-ietf-curdle-pkix-04
     *</li></li>
     * Key encoding: https://tools.ietf.org/html/rfc8032
     *</li></ul>
     *</p><p>
     * For keys in older formats, decoding and then re-encoding is sufficient to
     * migrate them to the canonical encoding.
     *</p>
     * Relevant spec quotes:
     *<pre>
     *  In the X.509 certificate, the subjectPublicKeyInfo field has the
     *  SubjectPublicKeyInfo type, which has the following ASN.1 syntax:
     *
     *  SubjectPublicKeyInfo  ::=  SEQUENCE  {
     *    algorithm         AlgorithmIdentifier,
     *    subjectPublicKey  BIT STRING
     *  }
     *</pre>
     *
     *<pre>
     *  AlgorithmIdentifier  ::=  SEQUENCE  {
     *    algorithm   OBJECT IDENTIFIER,
     *    parameters  ANY DEFINED BY algorithm OPTIONAL
     *  }
     *
     *  For all of the OIDs, the parameters MUST be absent.
     *</pre>
     *
     *<pre>
     *  id-Ed25519   OBJECT IDENTIFIER ::= { 1 3 101 112 }
     *</pre>
     *
     * @return 44 bytes for Ed25519, null for other curves
     */
    @Override
    public byte[] getEncoded() {
        if (!paramSpec.equals(RFC7748NamedCurveTable.getByName("Ed25519")))
            return null;
        int totlen = 12 + Abyte.length;
        byte[] rv = new byte[totlen];
        int idx = 0;
        // sequence
        rv[idx++] = 0x30;
        rv[idx++] = (byte) (totlen - 2);
        // Algorithm Identifier
        // sequence
        rv[idx++] = 0x30;
        rv[idx++] = 5;
        // OID
        // https://msdn.microsoft.com/en-us/library/windows/desktop/bb540809%28v=vs.85%29.aspx
        rv[idx++] = 0x06;
        rv[idx++] = 3;
        rv[idx++] = (1 * 40) + 3;
        rv[idx++] = 101;
        rv[idx++] = (byte) OID_ED25519;
        // params - absent
        // the key
        rv[idx++] = 0x03; // bit string
        rv[idx++] = (byte) (1 + Abyte.length);
        rv[idx++] = 0; // number of trailing unused bits
        System.arraycopy(Abyte, 0, rv, idx, Abyte.length);
        return rv;
    }

    /**
     * Extracts the public key bytes from the provided encoding.
     *<p>
     * This will decode data conforming to the current spec at
     * https://tools.ietf.org/html/draft-ietf-curdle-pkix-04
     * or the old spec at
     * https://tools.ietf.org/html/draft-josefsson-pkix-eddsa-04.
     *</p><p>
     * Contrary to draft-ietf-curdle-pkix-04, it WILL accept a parameter value
     * of NULL, as it is required for interoperability with the default Java
     * keystore. Other implementations MUST NOT copy this behaviour from here
     * unless they also need to read keys from the default Java keystore.
     *</p><p>
     * This is really dumb for now. It does not use a general-purpose ASN.1 decoder.
     * See also getEncoded().
     *</p>
     *
     * @return 32 bytes for Ed25519, throws for other curves
     */
    private static byte[] decode(byte[] d) throws InvalidKeySpecException {
        try {
            //
            // Setup and OID check
            //
            int totlen = 44;
            int idlen = 5;
            int doid = d[OID_BYTE];
            if (doid == OID_OLD) {
                totlen = 47;
                idlen = 8;
            } else if (doid == OID_ED25519) {
                // Detect parameter value of NULL
                if (d[IDLEN_BYTE] == 7) {
                    totlen = 46;
                    idlen = 7;
                }
            } else {
                throw new InvalidKeySpecException("unsupported key spec");
            }

            //
            // Pre-decoding check
            //
            if (d.length != totlen) {
                throw new InvalidKeySpecException("invalid key spec length");
            }

            //
            // Decoding
            //
            int idx = 0;
            if (d[idx++] != 0x30 ||
                d[idx++] != (totlen - 2) ||
                d[idx++] != 0x30 ||
                d[idx++] != idlen ||
                d[idx++] != 0x06 ||
                d[idx++] != 3 ||
                d[idx++] != (1 * 40) + 3 ||
                d[idx++] != 101) {
                throw new InvalidKeySpecException("unsupported key spec");
            }
            idx++; // OID, checked above
            // parameters only with old OID
            if (doid == OID_OLD) {
                if (d[idx++] != 0x0a ||
                    d[idx++] != 1 ||
                    d[idx++] != 1) {
                    throw new InvalidKeySpecException("unsupported key spec");
                }
            } else {
                // Handle parameter value of NULL
                //
                // Quote https://tools.ietf.org/html/draft-ietf-curdle-pkix-04 :
                //   For all of the OIDs, the parameters MUST be absent.
                //   Regardless of the defect in the original 1997 syntax,
                //   implementations MUST NOT accept a parameters value of NULL.
                //
                // But Java's default keystore puts it in (when decoding as
                // PKCS8 and then re-encoding to pass on), so we must accept it.
                if (idlen == 7) {
                    if (d[idx++] != 0x05 ||
                        d[idx++] != 0) {
                        throw new InvalidKeySpecException("unsupported key spec");
                    }
                }
            }
            if (d[idx++] != 0x03 ||
                d[idx++] != 33 ||
                d[idx++] != 0) {
                throw new InvalidKeySpecException("unsupported key spec");
            }
            byte[] rv = new byte[32];
            System.arraycopy(d, idx, rv, 0, 32);
            return rv;
        } catch (IndexOutOfBoundsException ioobe) {
            throw new InvalidKeySpecException(ioobe);
        }
    }

    @Override
    public RFC7748ParameterSpec getParams() {
        return paramSpec;
    }

    public GroupElement getA() {
        return A;
    }

    public GroupElement getNegativeA() {
        return Aneg;
    }

    public byte[] getAbyte() {
        return Abyte;
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(Abyte);
    }

    @Override
    public boolean equals(Object o) {
        if (o == this)
            return true;
        if (!(o instanceof RFC7748PublicKey))
            return false;
        RFC7748PublicKey pk = (RFC7748PublicKey) o;
        return Arrays.equals(Abyte, pk.getAbyte()) &&
               paramSpec.equals(pk.getParams());
    }
}
