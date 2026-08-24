package fr.tipe;

import javacard.framework.Shareable;

public interface ElGamalInterface extends Shareable{
    byte[] cmdEncrypt(byte[] apduBuff, short len);
    byte[] helloWorld();
    byte[] cmdDecrypt(byte[] apduBuff, short len);
}
