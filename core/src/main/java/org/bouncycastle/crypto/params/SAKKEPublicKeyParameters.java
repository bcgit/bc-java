package org.bouncycastle.crypto.params;

import java.math.BigInteger;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Hex;

/**
 * Represents the public parameters for the SAKKE (Sakai-Kasahara Key Encryption) scheme
 * as defined in RFC 6508. This class encapsulates the cryptographic domain parameters
 * and public key components required for SAKKE operations.
 * <p>
 * Contains the following public parameters (RFC 6508, Section 2.3):
 * <ul>
 *   <li>Prime modulus {@code p} defining the field F_p</li>
 *   <li>Subgroup order {@code q} (divides p+1)</li>
 *   <li>Base point {@code P} on the elliptic curve E(F_p)</li>
 *   <li>Pairing result {@code g = <P,P>}</li>
 *   <li>KMS Public Key {@code Z_S = [z_S]P}</li>
 *   <li>Security parameter {@code n} (SSV bit length)</li>
 *   <li>User Identifier</li>
 *   <li>Elliptic curve parameters (a = -3, b = 0)</li>
 * </ul>
 * </p>
 * <p>
 * The predefined parameters in this implementation correspond to the 128-bit security
 * level example from RFC 6509 Appendix A.
 * </p>
 *
 * @see <a href="https://tools.ietf.org/html/rfc6508">RFC 6508: Sakai-Kasahara Key Encryption</a>
 * @see <a href="https://tools.ietf.org/html/rfc6509">RFC 6509: MIKEY-SAKKE</a>
 */
public class SAKKEPublicKeyParameters
    extends AsymmetricKeyParameter
{
    /**
     * Prime modulus p defining the finite field F_p (RFC 6508, Section 2.1).
     * Value from RFC 6509 Appendix A.
     */
    static final BigInteger p = new BigInteger(
        "997ABB1F0A563FDA65C61198DAD0657A416C0CE19CB48261BE9AE358B3E01A2E" +
            "F40AAB27E2FC0F1B228730D531A59CB0E791B39FF7C88A19356D27F4A666A6D0" +
            "E26C6487326B4CD4512AC5CD65681CE1B6AFF4A831852A82A7CF3C521C3C09AA" +
            "9F94D6AF56971F1FFCE3E82389857DB080C5DF10AC7ACE87666D807AFEA85FEB", 16
    );

    /**
     * Subgroup order q (divides p+1) (RFC 6508, Section 2.1).
     * Value from RFC 6509 Appendix A.
     */
    static final BigInteger q = new BigInteger(
        "265EAEC7C2958FF69971846636B4195E905B0338672D20986FA6B8D62CF8068B" +
            "BD02AAC9F8BF03C6C8A1CC354C69672C39E46CE7FDF222864D5B49FD2999A9B4" +
            "389B1921CC9AD335144AB173595A07386DABFD2A0C614AA0A9F3CF14870F026A" +
            "A7E535ABD5A5C7C7FF38FA08E2615F6C203177C42B1EB3A1D99B601EBFAA17FB", 16
    );

    private static final BigInteger Px = new BigInteger(
        "53FC09EE332C29AD0A7990053ED9B52A2B1A2FD60AEC69C698B2F204B6FF7CBF" +
            "B5EDB6C0F6CE2308AB10DB9030B09E1043D5F22CDB9DFA55718BD9E7406CE890" +
            "9760AF765DD5BCCB337C86548B72F2E1A702C3397A60DE74A7C1514DBA66910D" +
            "D5CFB4CC80728D87EE9163A5B63F73EC80EC46C4967E0979880DC8ABEAE63895", 16
    );


    private static final BigInteger Py = new BigInteger(
        "0A8249063F6009F1F9F1F0533634A135D3E82016029906963D778D821E141178" +
            "F5EA69F4654EC2B9E7F7F5E5F0DE55F66B598CCF9A140B2E416CFF0CA9E032B9" +
            "70DAE117AD547C6CCAD696B5B7652FE0AC6F1E80164AA989492D979FC5A4D5F2" +
            "13515AD7E9CB99A980BDAD5AD5BB4636ADB9B5706A67DCDE75573FD71BEF16D7", 16
    );

    /**
     * Pairing result g = <P,P> computed using the Tate-Lichtenbaum pairing
     * (RFC 6508, Section 3.2). Value from RFC 6509 Appendix A.
     */
    private static final BigInteger g = new BigInteger(1, Hex.decode("66FC2A43 2B6EA392 148F1586 7D623068\n" +
        "               C6A87BD1 FB94C41E 27FABE65 8E015A87\n" +
        "               371E9474 4C96FEDA 449AE956 3F8BC446\n" +
        "               CBFDA85D 5D00EF57 7072DA8F 541721BE\n" +
        "               EE0FAED1 828EAB90 B99DFB01 38C78433\n" +
        "               55DF0460 B4A9FD74 B4F1A32B CAFA1FFA\n" +
        "               D682C033 A7942BCC E3720F20 B9B7B040\n" +
        "               3C8CAE87 B7A0042A CDE0FAB3 6461EA46"));

    /**
     * The elliptic curve E: y² = x³ - 3x over F_p (RFC 6508, Section 3.1).
     * Uses parameters from RFC 6509 Appendix A.
     */
    private static final ECCurve.Fp curve = new ECCurve.Fp(
        p,                                   // Prime p
        BigInteger.valueOf(-3).mod(p),             // a = -3
        BigInteger.ZERO, // ,
        g,                                  // Order of the subgroup (from RFC 6509)
        BigInteger.ONE                      // Cofactor = 1
    );

    /**
     * Base point P on the elliptic curve E(F_p) (RFC 6508, Section 3.1).
     * Coordinates from RFC 6509 Appendix A.
     */
    static final ECPoint P = curve.createPoint(Px, Py);
    /** KMS Public Key Z_S = [z_S]P (RFC 6508, Section 2.2) */
    private final ECPoint Z;
    /** User's Identifier (RFC 6508, Section 2.2) */
    private final BigInteger identifier; // User's identity
    /** Security parameter: SSV bit length (n = 128 bits) */
    private static final int n = 128;      // SSV bit length
    /** Hash function (SHA-256) used in SAKKE operations */
    private final Digest digest = new SHA256Digest();
    /**
     * Constructs SAKKE public key parameters with the specified identifier and KMS Public Key.
     *
     * @param identifier The user's identifier as defined in RFC 6508, Section 2.2.
     *                   Must be a valid integer in [2, q-1].
     * @param Z          The KMS Public Key Z_S = [z_S]P (RFC 6508, Section 2.2).
     *                   Must be a valid point on the curve E(F_p).
     */
    public SAKKEPublicKeyParameters(BigInteger identifier, ECPoint Z)
    {
        super(false);
        this.identifier = identifier;
        this.Z = Z;
    }

    /**
     * @return The user's identifier (RFC 6508, Section 2.2)
     */
    public BigInteger getIdentifier()
    {
        return identifier;
    }

    /**
     * @return The KMS Public Key Z_S = [z_S]P (RFC 6508, Section 2.2)
     */
    public ECPoint getZ()
    {
        return Z;
    }

    /**
     * @return The elliptic curve E(F_p) with parameters from RFC 6509 Appendix A
     */
    public ECCurve getCurve()
    {
        return curve;
    }

    /**
     * @return The base point P on E(F_p) (RFC 6508, Section 3.1)
     */
    public ECPoint getPoint()
    {
        return P;
    }

    /**
     * @return Prime modulus p defining the field F_p (RFC 6508, Section 2.1)
     */
    public BigInteger getPrime()
    {
        return p;
    }

    /**
     * @return Subgroup order q (divides p+1) (RFC 6508, Section 2.1)
     */
    public BigInteger getQ()
    {
        return q;
    }

    /**
     * @return Security parameter n (SSV bit length = 128 bits)
     */
    public int getN()
    {
        return n;
    }

    /**
     * @return The hash function (SHA-256) used in SAKKE operations
     */
    public Digest getDigest()
    {
        return digest;
    }

    /**
     * @return The pairing result g = <P,P> (RFC 6508, Section 3.2)
     */
    public BigInteger getG()
    {
        return g;
    }
}
