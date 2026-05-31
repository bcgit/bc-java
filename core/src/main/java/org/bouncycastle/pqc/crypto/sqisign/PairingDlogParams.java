package org.bouncycastle.pqc.crypto.sqisign;


/**
 * Parameter bundle for {@code ec_dlog_2_tate} / {@code ec_dlog_2_weil}.
 * Java port of {@code pairing_dlog_params_t} from
 * {@code src/ec/ref/include/biextension.h}.
 *
 * <p>Two bases {@code (P, Q)} and {@code (R, S)} of the 2^e-torsion are
 * tracked together with the inverses of their x-coordinates and the four
 * difference points required by the biextension pairing pipeline.</p>
 */
final class PairingDlogParams
{
    /**
     * Points have order 2^e.
     */
    public int e;
    /**
     * x-only basis (P, Q, P-Q).
     */
    public final EcBasis PQ;
    /**
     * x-only basis (R, S, R-S).
     */
    public final EcBasis RS;
    /**
     * Four difference points: x(P-R), x(P-S), x(R-Q), x(S-Q).
     */
    public final DiffPoints diff;
    /**
     * PZ / PX (inverse of x-coordinate of P after normalisation).
     */
    public final Fp2 ixP;
    /**
     * QZ / QX.
     */
    public final Fp2 ixQ;
    /**
     * RZ / RX.
     */
    public final Fp2 ixR;
    /**
     * SZ / SX.
     */
    public final Fp2 ixS;
    /**
     * Normalised curve cache ((A+2)/4 : 1).
     */
    public final EcPoint A24;

    public PairingDlogParams()
    {
        this.e = 0;
        this.PQ = new EcBasis();
        this.RS = new EcBasis();
        this.diff = new DiffPoints();
        this.ixP = Fp2.zero();
        this.ixQ = Fp2.zero();
        this.ixR = Fp2.zero();
        this.ixS = Fp2.zero();
        this.A24 = new EcPoint();
    }

    /**
     * Java mirror of {@code pairing_dlog_diff_points_t}.
     */
    public static final class DiffPoints
    {
        public final EcPoint PmR = new EcPoint();
        public final EcPoint PmS = new EcPoint();
        public final EcPoint RmQ = new EcPoint();
        public final EcPoint SmQ = new EcPoint();
    }
}
