package org.bouncycastle.mls.protocol;

import org.bouncycastle.mls.codec.MLSInputStream;
import org.bouncycastle.mls.codec.MLSOutputStream;

import java.io.IOException;

public class PreSharedKeyID implements MLSInputStream.Readable, MLSOutputStream.Writable {

    public static class External {
        public final byte[] externalPSKID;

        public External(byte[] externalPSKID) {
            this.externalPSKID = externalPSKID;
        }
    }

    public static class Resumption {
        public final ResumptionPSKUsage resumptionPSKUsage;
        public final byte[] pskGroupID;
        public final long pskEpoch;

        public Resumption(ResumptionPSKUsage resumptionPSKUsage, byte[] pskGroupID, long pskEpoch) {
            this.resumptionPSKUsage = resumptionPSKUsage;
            this.pskGroupID = pskGroupID;
            this.pskEpoch = pskEpoch;
        }
    }

    public final PSKType pskType;
    public final External external;
    public final Resumption resumption;
    public final byte[] pskNonce;

    PreSharedKeyID(PSKType pskType, External external, Resumption resumption, byte[] pskNonce) {
        this.pskType = pskType;
        this.external = external;
        this.resumption = resumption;
        this.pskNonce = pskNonce;
    }

    public static PreSharedKeyID external(byte[] externalPSKID, byte[] pskNonce) {
        External external = new External(externalPSKID);
        return new PreSharedKeyID(PSKType.EXTERNAL, external, null, pskNonce);
    }

    public static PreSharedKeyID resumption(ResumptionPSKUsage resumptionPSKUsage, byte[] pskGroupID, long pskEpoch, byte[] pskNonce) {
        Resumption resumptionVal = new Resumption(resumptionPSKUsage, pskGroupID, pskEpoch);
        return new PreSharedKeyID(PSKType.RESUMPTION, null, resumptionVal, pskNonce);
    }

    @SuppressWarnings("unused")
    public PreSharedKeyID(MLSInputStream stream) throws IOException {
        pskType = (PSKType) stream.read(PSKType.class);
        switch (this.pskType) {
            case EXTERNAL:
                byte[] externalPSKID = stream.readOpaque();
                external = new External(externalPSKID);
                resumption = null;
                break;

            case RESUMPTION:
                ResumptionPSKUsage resumptionPSKUsage = (ResumptionPSKUsage) stream.read(ResumptionPSKUsage.class);
                byte[] pskGroupID = stream.readOpaque();
                long pskEpoch = (long) stream.read(long.class);

                external = null;
                resumption = new Resumption(resumptionPSKUsage, pskGroupID, pskEpoch);
                break;

            default:
                throw new IOException("Invalid PSKType");
        }

        pskNonce = stream.readOpaque();
    }

    @Override
    public void writeTo(MLSOutputStream stream) throws IOException {
        stream.write(pskType);
        switch (pskType) {
            case EXTERNAL:
                stream.writeOpaque(external.externalPSKID);
                break;

            case RESUMPTION:
                stream.write(resumption.resumptionPSKUsage);
                stream.writeOpaque(resumption.pskGroupID);
                stream.write(resumption.pskEpoch);
                break;
        }

        stream.writeOpaque(pskNonce);
    }
}
