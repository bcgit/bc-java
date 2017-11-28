package org.bouncycastle.tls;

public class NegotiatedTokenBinding {

    String selectedKeyParameter;

    public byte[] exportKeyingMaterial;

    public byte[] getExportKeyingMaterial() {
        return exportKeyingMaterial;
    }

    public void setExportKeyingMaterial(byte[] exportKeyingMaterial) {
        this.exportKeyingMaterial = exportKeyingMaterial;
    }

    public int MajorProtocolVerison=0;
    public int MinorProtocolVerison=13;

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

        if(serverdata.length !=4){
            throw new TlsFatalAlert(AlertDescription.unsupported_extension);
        }
        this.setMajorProtocolVerison(serverdata[0]);
        this.setMinorProtocolVerison(serverdata[1]);
        if(serverdata[3]==0){
            this.setSelectedKeyParameter("rsa2048_pcks15");
        }else if (serverdata[3]==1){
            this.setSelectedKeyParameter("rsa2048_pss");
        }else if (serverdata[3]==2){
            this.setSelectedKeyParameter("rsa2048_ecdsap256");
        }else{
            throw new TlsFatalAlert(AlertDescription.unsupported_extension);
        }
        return this;
    }
}
