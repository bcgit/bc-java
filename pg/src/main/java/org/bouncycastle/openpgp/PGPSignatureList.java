package org.bouncycastle.openpgp;

/**
 * A list of PGP signatures - normally in the signature block after literal data.
 */
public class PGPSignatureList
{
    PGPSignature[]    sigs;
    
    public PGPSignatureList(
        PGPSignature[]    sigs)
    {
        this.sigs = new PGPSignature[sigs.length];
        
        System.arraycopy(sigs, 0, this.sigs, 0, sigs.length);
    }
    
    public PGPSignatureList(
        PGPSignature    sig)
    {
        this.sigs = new PGPSignature[1];
        this.sigs[0] = sig;
    }
    
    public PGPSignature get(
        int    index)
    {
        return sigs[index];
    }
    
    public int size()
    {
        return sigs.length;
    }
    
    public boolean isEmpty()
    {
        return (sigs.length == 0);
    }
}
