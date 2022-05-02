package org.bouncycastle.pqc.crypto.picnic;

class View
{
    int[] inputShare;
    byte[] communicatedBits;
    int[] outputShare;
    public View(PicnicEngine engine)
    {
        inputShare = new int[engine.stateSizeBytes] ;
        communicatedBits = new byte[engine.andSizeBytes];
        outputShare = new int[engine.stateSizeBytes] ;
    }
}
