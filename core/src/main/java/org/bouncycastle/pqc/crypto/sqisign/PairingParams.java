package org.bouncycastle.pqc.crypto.sqisign;


/**
 * Parameter bundle for the biextension-based pairing routines. Java port of
 * C {@code pairing_params_t} from {@code biextension.h}.
 */
final class PairingParams
{
    public int e;
    public final EcPoint P;
    public final EcPoint Q;
    public final EcPoint PQ;
    public final Fp2 ixP;
    public final Fp2 ixQ;
    public final EcPoint A24;

    public PairingParams()
    {
        this.e = 0;
        this.P = new EcPoint();
        this.Q = new EcPoint();
        this.PQ = new EcPoint();
        this.ixP = Fp2.zero();
        this.ixQ = Fp2.zero();
        this.A24 = new EcPoint();
    }
}
