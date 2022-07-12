package org.bouncycastle.bcpg;

public interface AEADAlgorithmTags
{
    int EAX = 1;    // EAX (IV len: 16 octets, Tag len: 16 octets)
    int OCB = 2;    // OCB (IV len: 15 octets, Tag len: 16 octets)
    int GCM = 3;    // GCM (IV len: 12 octets, Tag len: 16 octets)
}
