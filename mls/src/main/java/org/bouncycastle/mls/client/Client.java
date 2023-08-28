package org.bouncycastle.mls.client;

import org.bouncycastle.mls.KeyScheduleEpoch;
import org.bouncycastle.mls.codec.KeyPackage;
import org.bouncycastle.mls.codec.Proposal;
import org.bouncycastle.mls.crypto.CipherSuite;

import java.io.IOException;

public class Client
{
    KeyPackage keyPackage;
    KeyScheduleEpoch member;
    Group group;

    KeyPackage getKeyPackage()
    {
        return keyPackage;
    }

    public Client()
    {
    }

    public Group createNewGroup(CipherSuite suite)
            throws IOException, IllegalAccessException
    {
        member = KeyScheduleEpoch.forCreator(suite);
        group = new Group(this);
        return group;
    }

    public void addMember(Client memberNew)
    {
        // Process Add Proposal
        Proposal.Add add = addProposal(memberNew.getKeyPackage());

        // Commit Add Proposal

        // Send Welcome to added member

        // Group send all members except newMember
        // the add proposal
        // the commited add proposal

    }

    private Proposal.Add addProposal(KeyPackage keyPackage)
    {
        //TODO: Check that  validity of the signed key package

        //TODO: Check if the Key Package supports the group (capabilities)

        //TODO: Check if the Key Package supports the group extensions

        return new Proposal.Add(keyPackage);
    }
}
