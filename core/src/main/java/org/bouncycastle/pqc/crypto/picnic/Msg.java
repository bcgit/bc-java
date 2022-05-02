package org.bouncycastle.pqc.crypto.picnic;

class Msg
{
    byte[][] msgs; // One for each player
    int pos;
    int unopened;  // Index of the unopened party, or -1 if all parties opened (when signing)
    public Msg(PicnicEngine engine)
    {
        msgs = new byte[engine.numMPCParties][engine.andSizeBytes];
        pos = 0;
        unopened = -1;
    }
}