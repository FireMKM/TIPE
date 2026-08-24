package fr.tipe;

import javacard.framework.*;
import javacard.security.*;
import javacardx.apdu.ExtendedLength;
import javacardx.crypto.Cipher;

public class BenchmarkApplet extends Applet implements ExtendedLength {

    private static final byte[] ELGAMAL_APPLET_AID = {
            (byte)0xFF, (byte)0x53, (byte)0x56, (byte)0x6F, (byte)0x78, (byte)0xFF, (byte)0x22, (byte)0x12, (byte)0x02
    };

    private static final byte CRYPTO_CLA = (byte) 0x22;
    private static final byte RSA_INS = (byte) 0x10;
    private static final byte ELGAMAL_INS = (byte) 0x20;

    private ElGamalInterface elGamalApp;

    private final RSAPublicKey rsaPublicKey;
    private final RSAPrivateKey rsaPrivateKey;
    private final Cipher rsaCipher;

    private final static byte[] HELLO_WORLD_MESSAGE = { (byte) 0x62, (byte) 0x6F, (byte) 0x6E, (byte) 0x6A, (byte) 0x6F, (byte) 0x75, (byte) 0x72 };
    private final static byte HELLO_WORLD = (byte) 0xFF;

    private final byte[] resultArray_128;
    private final byte[] elgamalResult;
    private final byte[] elgamalOutput;

    private boolean isBufferAllZeros(byte[] buffer) {
        for (short i = 0; i < (short)buffer.length; i++) {  // Pas de boucle enhanced for car incompatible avec l'API JVC
            if (buffer[i] != (byte)0x00) {
                return false;
            }
        }
        return true;
    }

    private void encryptRSA(byte[] inBuff, short InOffset, short inLength, byte[] outBuff) {
        rsaCipher.init(rsaPublicKey, Cipher.MODE_ENCRYPT);
        rsaCipher.doFinal(inBuff, InOffset, inLength, outBuff, (short) 0);
    }

    private void decryptRSA(byte[] inBuff, short InOffset, short inLength, byte[] outBuff) {
        rsaCipher.init(rsaPrivateKey, Cipher.MODE_DECRYPT);
        rsaCipher.doFinal(inBuff, InOffset, inLength, outBuff, (short) 0);
    }

    private void returnData (APDU apdu, byte[] buffer, byte[] retdata, short retOff, short length) {
        Util.arrayCopy(retdata, retOff, buffer, ISO7816.OFFSET_CDATA, length);
        apdu.setOutgoing();
        apdu.setOutgoingLength(length);
        apdu.sendBytes(ISO7816.OFFSET_CDATA, length);
    }

    private void returnLongData (APDU apdu, byte[] buffer, byte[] retdata, short length) { // for extended lenght apdu, help from Claude
        Util.arrayCopy(retdata, (short) 0, buffer, ISO7816.OFFSET_CDATA, length);
        apdu.setOutgoing();
        apdu.setOutgoingLength(length);
        apdu.sendBytesLong(buffer, ISO7816.OFFSET_CDATA, length);
    }

    public static void install (byte[] bArray, short bOffset, byte bLength) { new BenchmarkApplet(); }

    protected BenchmarkApplet() {
        register();

        resultArray_128 = JCSystem.makeTransientByteArray((short)128, JCSystem.CLEAR_ON_RESET);
        elgamalResult = new byte[(short)256];
        elgamalOutput = new byte[(short)128];
        try {
            AID elGamalAppletAID = JCSystem.lookupAID(ELGAMAL_APPLET_AID, (short) 0, (byte) ELGAMAL_APPLET_AID.length);
            if (elGamalAppletAID != null) {
                this.elGamalApp = (ElGamalInterface) JCSystem.getAppletShareableInterfaceObject(elGamalAppletAID, (byte) 0x01);
            }
            if (this.elGamalApp == null) {
                ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
            }
        } catch (Exception e) {ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);}

        // ===== RSA =====
        KeyPair RSA_KeyPair = new KeyPair(KeyPair.ALG_RSA, KeyBuilder.LENGTH_RSA_1024);
        RSA_KeyPair.genKeyPair();

        rsaPublicKey = (RSAPublicKey) RSA_KeyPair.getPublic();
        rsaPrivateKey = (RSAPrivateKey) RSA_KeyPair.getPrivate();
        rsaCipher = Cipher.getInstance(Cipher.ALG_RSA_PKCS1, false);
    }

    @Override
    public void process (APDU apdu) throws ISOException {
        if (selectingApplet()) return;

        byte[] buffer = apdu.getBuffer();

        if (buffer[ISO7816.OFFSET_CLA] != CRYPTO_CLA) {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }

        switch (buffer[ISO7816.OFFSET_INS]) {
            case RSA_INS:
                if (buffer[ISO7816.OFFSET_LC] == (byte)0) ISOException.throwIt(ISO7816.SW_DATA_INVALID);
                else {
                    short totalBytesRead = apdu.setIncomingAndReceive();
                    short dataOffset = apdu.getOffsetCdata();
                    if (buffer[ISO7816.OFFSET_P1] == (byte) 0x01) {
                        encryptRSA(buffer, dataOffset, totalBytesRead, resultArray_128);
                        returnData(apdu, buffer, resultArray_128, (short)0, (short)128);

                    } else if (buffer[ISO7816.OFFSET_P1] == (byte) 0x02) {
                        if (buffer[ISO7816.OFFSET_LC] == (byte)128) {
                            Util.arrayFill(resultArray_128, (short)0, (short)128, (byte)0x00);
                            decryptRSA(buffer, dataOffset, totalBytesRead, resultArray_128);
                            returnData(apdu, buffer, resultArray_128, (short)0, (short)128);

                        } else ISOException.throwIt(ISO7816.SW_DATA_INVALID);
                    } else ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
                    // Select applet: 00 A4 04 00 09 FF 53 56 6F 78 FF 22 11 01
                    // ElGamal encrypt "bonjour": 22 20 01 00 07 42 6f 6e 6a 6f 75 72 00
                    // ElGamal get C1: 22 20 01 C1 80
                    // ElGamal get C1: 22 20 01 C2 80
                    // ElGamal decrypt: 22 20 02 00
                    // RSA encrypt "bonjour": 22 10 01 00 07 42 6f 6e 6a 6f 75 72 80
                    // 22 FF 00 00 07
                }
                break;

            case ELGAMAL_INS:
                if (buffer[ISO7816.OFFSET_P1] == (byte)0x01) {
                    if (buffer[ISO7816.OFFSET_P2] == (byte)0x00) {
                        if (buffer[ISO7816.OFFSET_LC] == (byte)0) ISOException.throwIt(ISO7816.SW_DATA_INVALID);
                        else {
                            short totalBytesRead = apdu.setIncomingAndReceive();
                            byte[] tempRes = this.elGamalApp.cmdEncrypt(buffer, totalBytesRead);
                            Util.arrayCopy(tempRes, (short)0, elgamalResult, (short)0, (short)256);
                        }
                    } else if (buffer[ISO7816.OFFSET_P2] == (byte)0xC1) {
                        if (isBufferAllZeros(elgamalResult)) {
                            ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
                        } else {
                            returnData(apdu, buffer, elgamalResult, (short)0, (short)128);
                        }
                    } else if (buffer[ISO7816.OFFSET_P2] == (byte)0xC2) {
                        if (isBufferAllZeros(elgamalResult)) {
                            ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
                        } else {
                            returnData(apdu, buffer, elgamalResult, (short)128, (short)128);
                        }
                    } else ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
                } else if (buffer[ISO7816.OFFSET_P1] == (byte)0x02) {
                    if (buffer[ISO7816.OFFSET_P2] == (byte)0x00) {
                        byte[] tempRes = this.elGamalApp.cmdDecrypt(elgamalResult, (short)elgamalResult.length);
                        returnData(apdu, buffer, tempRes, (short)0, (short)128);
                    } else ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
                } else ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
                break;

            case HELLO_WORLD:
                if (buffer[ISO7816.OFFSET_P1] == (byte) 0x01) returnData(apdu, buffer, HELLO_WORLD_MESSAGE, (short)0, (short)7);
                else if (buffer[ISO7816.OFFSET_P1] == (byte) 0x02) returnData(apdu, buffer, this.elGamalApp.helloWorld(), (short)0, (short)7);
                else ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
                break;
            default: {
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
                break;
            }
        }

    }

}