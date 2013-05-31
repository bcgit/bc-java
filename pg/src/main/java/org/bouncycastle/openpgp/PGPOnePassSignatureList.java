package org.bouncycastle.openpgp;

/**
 * Holder for a list of PGPOnePassSignatures
 */
public class PGPOnePassSignatureList
{
    PGPOnePassSignature[]    sigs;
    
    public PGPOnePassSignatureList(
        PGPOnePassSignature[]    sigs)
    {
        this.sigs = new PGPOnePassSignature[sigs.length];
        
        System.arraycopy(sigs, 0, this.sigs, 0, sigs.length);
    }
    
    public PGPOnePassSignatureList(
        PGPOnePassSignature    sig)
    {
        this.sigs = new PGPOnePassSignature[1];
        this.sigs[0] = sig;
    }
    
    public PGPOnePassSignature get(
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
