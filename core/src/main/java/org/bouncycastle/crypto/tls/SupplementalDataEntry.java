package org.bouncycastle.crypto.tls;

public class SupplementalDataEntry
{

    private int supp_data_type;
    private byte[] data;

    public SupplementalDataEntry(int supp_data_type, byte[] data)
    {
        this.supp_data_type = supp_data_type;
        this.data = data;
    }

    public int getDataType()
    {
        return supp_data_type;
    }

    public byte[] getData()
    {
        return data;
    }
}
