package org.bouncycastle.tls;

/**
 * This class captures the negotiated parameters from the TLS handshake
 */
public class NegotiatedTokenBinding {

    private String selectedKeyParameter;
    protected String RSA2048_PCKS15 = "rsa2048_pcks15";
    protected String RSA2048_PSS = "rsa2048_pss";
    protected String RSA2048_ECDSAP256 = "rsa2048_ecdsap256";

    public byte[] exportKeyingMaterial;

    public byte[] getExportKeyingMaterial() {
        return exportKeyingMaterial;
    }

    public void setExportKeyingMaterial(byte[] exportKeyingMaterial) {
        this.exportKeyingMaterial = exportKeyingMaterial;
    }

    public int MajorProtocolVerison = 0;
    public int MinorProtocolVerison = 13;

    public String getSelectedKeyParameter() {
        return selectedKeyParameter;
    }

    public void setSelectedKeyParameter(String selectedKeyParameter) {
        this.selectedKeyParameter = selectedKeyParameter;
    }

    public int getMajorProtocolVerison() {
        return MajorProtocolVerison;
    }

    public void setMajorProtocolVerison(int majorProtocolVerison) {
        MajorProtocolVerison = majorProtocolVerison;
    }

    public int getMinorProtocolVerison() {
        return MinorProtocolVerison;
    }

    public void setMinorProtocolVerison(int minorProtocolVerison) {
        MinorProtocolVerison = minorProtocolVerison;
    }

    public NegotiatedTokenBinding decode(int[] serverdata) throws TlsFatalAlert {

        if (serverdata.length != 4) {
            throw new TlsFatalAlert(AlertDescription.unsupported_extension);
        }
        this.setMajorProtocolVerison(serverdata[0]);
        this.setMinorProtocolVerison(serverdata[1]);
        if (serverdata[3] == 0) {
            this.setSelectedKeyParameter(RSA2048_PCKS15);
        } else if (serverdata[3] == 1) {
            this.setSelectedKeyParameter(RSA2048_PSS);
        } else if (serverdata[3] == 2) {
            this.setSelectedKeyParameter(RSA2048_ECDSAP256);
        } else {
            throw new TlsFatalAlert(AlertDescription.unsupported_extension);
        }
        return this;
    }
}
