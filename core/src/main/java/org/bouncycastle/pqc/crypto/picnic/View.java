package org.bouncycastle.pqc.crypto.picnic;

class View
{
    final int[] inputShare;
    final byte[] communicatedBits;
    final int[] outputShare;
    public View(PicnicEngine engine)
    {
        inputShare = new int[engine.stateSizeWords] ;
        communicatedBits = new byte[engine.andSizeBytes];
        outputShare = new int[engine.stateSizeWords] ;
    }
}
