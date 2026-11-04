package co.edu.icesi.signer.gui;

/** Remembers whether the user has already been through the guide. */
interface GuideState {

    boolean seen();

    void markSeen();
}
