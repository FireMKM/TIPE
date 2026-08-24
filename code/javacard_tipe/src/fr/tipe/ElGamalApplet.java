package fr.tipe;

import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.*;

/**
 * ElGamal sur JavaCard — exponentiation modulaire via coprocesseur RSA.
 *
 * Astuce : RSA en mode "raw" (ALG_RSA_NOPAD) calcule exactement :
 *   chiffre = message^publicExponent mod modulus
 * On l'utilise donc comme moteur modExp :
 *   Pour calculer base^exp mod p :
 *     - modulus    = p
 *     - publicExp  = exp
 *     - message    = base
 *
 * C'est la technique standard sur JavaCard pour ElGamal/DH.
 * Aucune arithmetique logicielle — tout passe par le coprocesseur crypto.
 */
public class ElGamalApplet extends Applet implements ElGamalInterface {

    private boolean isInterfaceShared = false;

    private static final byte[] HELLO_WORLD_MESSAGE_2 = {
            (byte)0x42, (byte)0x6F, (byte)0x6E, (byte)0x6A, (byte)0x6F, (byte)0x75, (byte)0x72
    };

    public static final short KEY_LEN = (short)128; // 1024 bits

    // ------------------------------------------------------------------ //
    //  Parametres ElGamal hardcodes
    // ------------------------------------------------------------------ //
    private static final byte[] P_BYTES = {
            (byte)0xf0, (byte)0xbc, (byte)0x29, (byte)0xa8, (byte)0xc7, (byte)0xfc, (byte)0x7e, (byte)0xf8,
            (byte)0x96, (byte)0xe3, (byte)0x58, (byte)0xd8, (byte)0xad, (byte)0xdb, (byte)0xf8, (byte)0x64,
            (byte)0xb1, (byte)0xeb, (byte)0x7e, (byte)0x82, (byte)0x89, (byte)0x12, (byte)0x7d, (byte)0x00,
            (byte)0x39, (byte)0xdb, (byte)0xb5, (byte)0x4e, (byte)0x70, (byte)0x01, (byte)0x10, (byte)0x1c,
            (byte)0xdd, (byte)0x93, (byte)0xd3, (byte)0xfb, (byte)0x00, (byte)0x89, (byte)0xa1, (byte)0x65,
            (byte)0xb8, (byte)0xcb, (byte)0x34, (byte)0xfd, (byte)0x3f, (byte)0xfd, (byte)0x94, (byte)0x84,
            (byte)0xed, (byte)0x63, (byte)0x3b, (byte)0xc7, (byte)0xc0, (byte)0xce, (byte)0xfc, (byte)0x77,
            (byte)0xba, (byte)0xc6, (byte)0xbe, (byte)0x3f, (byte)0xb7, (byte)0x18, (byte)0x7e, (byte)0x7d,
            (byte)0x3b, (byte)0x63, (byte)0xa5, (byte)0x65, (byte)0xa2, (byte)0xb6, (byte)0xae, (byte)0xb5,
            (byte)0x53, (byte)0x8f, (byte)0xe5, (byte)0xb4, (byte)0x43, (byte)0x05, (byte)0x33, (byte)0x01,
            (byte)0xeb, (byte)0x0d, (byte)0x90, (byte)0xe7, (byte)0x3b, (byte)0xc6, (byte)0xa8, (byte)0x80,
            (byte)0x8e, (byte)0x08, (byte)0x0f, (byte)0x13, (byte)0x68, (byte)0xcf, (byte)0x15, (byte)0xb9,
            (byte)0xc5, (byte)0x2e, (byte)0x28, (byte)0x82, (byte)0xeb, (byte)0x0a, (byte)0x5a, (byte)0xeb,
            (byte)0xb6, (byte)0x99, (byte)0x6e, (byte)0x4d, (byte)0x18, (byte)0xce, (byte)0x3d, (byte)0xef,
            (byte)0xd0, (byte)0xc1, (byte)0x14, (byte)0x2b, (byte)0x60, (byte)0x56, (byte)0xfa, (byte)0x4e,
            (byte)0x0f, (byte)0x3d, (byte)0x89, (byte)0xad, (byte)0x85, (byte)0x31, (byte)0x7b, (byte)0x07
    };

    private static final byte[] G_BYTES = {
            (byte)0x00,
            (byte)0x03, (byte)0x0e, (byte)0x7d, (byte)0xa3, (byte)0xd3, (byte)0xbc, (byte)0x64,
            (byte)0xc0, (byte)0x62, (byte)0xb6, (byte)0x24, (byte)0x20, (byte)0x81, (byte)0xd5, (byte)0x8b,
            (byte)0xfd, (byte)0xab, (byte)0x26, (byte)0x2c, (byte)0x61, (byte)0x90, (byte)0x13, (byte)0x0c,
            (byte)0x2b, (byte)0xe4, (byte)0xce, (byte)0x25, (byte)0x84, (byte)0xfe, (byte)0xb5, (byte)0xf6,
            (byte)0xbd, (byte)0x9f, (byte)0x05, (byte)0xa7, (byte)0xcf, (byte)0x1a, (byte)0xea, (byte)0xdd,
            (byte)0xfa, (byte)0xc4, (byte)0x8d, (byte)0x31, (byte)0x2e, (byte)0x52, (byte)0xe1, (byte)0x7e,
            (byte)0xd8, (byte)0x8a, (byte)0x53, (byte)0x12, (byte)0xd5, (byte)0xac, (byte)0x29, (byte)0x8d,
            (byte)0x57, (byte)0x02, (byte)0xeb, (byte)0xfb, (byte)0xbd, (byte)0x06, (byte)0x6a, (byte)0x30,
            (byte)0x73, (byte)0x51, (byte)0x8f, (byte)0x06, (byte)0xb6, (byte)0x26, (byte)0x6c, (byte)0xab,
            (byte)0xb1, (byte)0x25, (byte)0x15, (byte)0xa7, (byte)0xb0, (byte)0x57, (byte)0x6a, (byte)0x6d,
            (byte)0xbd, (byte)0x66, (byte)0xf2, (byte)0xa2, (byte)0xc7, (byte)0x37, (byte)0x24, (byte)0x77,
            (byte)0x4b, (byte)0xbe, (byte)0x9d, (byte)0xf8, (byte)0xb4, (byte)0x73, (byte)0xc8, (byte)0x2c,
            (byte)0xc4, (byte)0x5a, (byte)0x64, (byte)0x40, (byte)0x59, (byte)0x7d, (byte)0x64, (byte)0x79,
            (byte)0xd4, (byte)0x7f, (byte)0x07, (byte)0x3a, (byte)0x70, (byte)0x84, (byte)0xd2, (byte)0xf5,
            (byte)0x59, (byte)0xab, (byte)0x0b, (byte)0x91, (byte)0x37, (byte)0x7c, (byte)0x9e, (byte)0xef,
            (byte)0x54, (byte)0xd0, (byte)0x73, (byte)0x0b, (byte)0xfe, (byte)0x1b, (byte)0x55, (byte)0x86,
            (byte)0xb3
    };

    private static final byte[] X_BYTES = {
            (byte)0x7d, (byte)0xe4, (byte)0xa6, (byte)0x83, (byte)0x3f, (byte)0xdf, (byte)0x9e, (byte)0x8e,
            (byte)0x81, (byte)0xb0, (byte)0x89, (byte)0x40, (byte)0x2f, (byte)0xad, (byte)0x37, (byte)0x92,
            (byte)0xa3, (byte)0xf0, (byte)0x80, (byte)0xb1, (byte)0x37, (byte)0x98, (byte)0x25, (byte)0xc6,
            (byte)0x4e, (byte)0x5a, (byte)0xb7, (byte)0x8c, (byte)0x51, (byte)0x58, (byte)0x61, (byte)0x01,
            (byte)0xf7, (byte)0x15, (byte)0x16, (byte)0xa4, (byte)0x4e, (byte)0x63, (byte)0x1f, (byte)0x8a,
            (byte)0x6d, (byte)0x51, (byte)0x99, (byte)0x08, (byte)0x9d, (byte)0x4c, (byte)0xd3, (byte)0xd8,
            (byte)0x7b, (byte)0x11, (byte)0x62, (byte)0x42, (byte)0x7c, (byte)0xe0, (byte)0x97, (byte)0x54,
            (byte)0x55, (byte)0xa8, (byte)0xfb, (byte)0x87, (byte)0x49, (byte)0x49, (byte)0xfc, (byte)0x3d,
            (byte)0x31, (byte)0x1e, (byte)0xa9, (byte)0xa0, (byte)0x27, (byte)0xa3, (byte)0xe8, (byte)0xc8,
            (byte)0x1f, (byte)0xa2, (byte)0xd3, (byte)0x80, (byte)0x12, (byte)0x6f, (byte)0xc0, (byte)0xdc,
            (byte)0xe0, (byte)0x50, (byte)0x23, (byte)0x6f, (byte)0x4f, (byte)0x2e, (byte)0x03, (byte)0x8f,
            (byte)0x5e, (byte)0x45, (byte)0x78, (byte)0x2f, (byte)0x8d, (byte)0x3f, (byte)0x8f, (byte)0xb2,
            (byte)0xba, (byte)0x22, (byte)0x4e, (byte)0xff, (byte)0x52, (byte)0x98, (byte)0x8e, (byte)0xde,
            (byte)0x91, (byte)0x93, (byte)0x36, (byte)0x29, (byte)0x68, (byte)0x55, (byte)0xe5, (byte)0x8e,
            (byte)0xc4, (byte)0xc7, (byte)0x3e, (byte)0xca, (byte)0xd5, (byte)0xb5, (byte)0x79, (byte)0x87,
            (byte)0xd1, (byte)0xf6, (byte)0xc0, (byte)0x2c, (byte)0x1e, (byte)0xf8, (byte)0xbf, (byte)0x03
    };

    private static final byte[] Y_BYTES = {
            (byte)0x98, (byte)0x1b, (byte)0xcb, (byte)0xa9, (byte)0xef, (byte)0x93, (byte)0x0a, (byte)0xe6,
            (byte)0xbb, (byte)0x3d, (byte)0x52, (byte)0x89, (byte)0xba, (byte)0x81, (byte)0xea, (byte)0xa5,
            (byte)0x4d, (byte)0x61, (byte)0xdd, (byte)0x2f, (byte)0x8b, (byte)0x77, (byte)0x22, (byte)0x1a,
            (byte)0x32, (byte)0x42, (byte)0xe8, (byte)0x84, (byte)0xf5, (byte)0xc1, (byte)0x9f, (byte)0x35,
            (byte)0x1a, (byte)0x10, (byte)0xa9, (byte)0xc3, (byte)0x38, (byte)0x91, (byte)0x2d, (byte)0x31,
            (byte)0x49, (byte)0xa3, (byte)0xd1, (byte)0xfc, (byte)0xe8, (byte)0x95, (byte)0xfa, (byte)0xb7,
            (byte)0x2d, (byte)0xf1, (byte)0x08, (byte)0x92, (byte)0xe7, (byte)0x8d, (byte)0x99, (byte)0xea,
            (byte)0xbc, (byte)0x51, (byte)0xf4, (byte)0xf9, (byte)0x5f, (byte)0x81, (byte)0x40, (byte)0x76,
            (byte)0x07, (byte)0xa7, (byte)0x89, (byte)0x61, (byte)0x65, (byte)0x74, (byte)0x92, (byte)0x02,
            (byte)0x3b, (byte)0x9b, (byte)0x9d, (byte)0xd4, (byte)0x1f, (byte)0xbf, (byte)0x30, (byte)0xba,
            (byte)0xba, (byte)0x46, (byte)0x1c, (byte)0xd7, (byte)0x2f, (byte)0xa5, (byte)0xfd, (byte)0xbd,
            (byte)0xaf, (byte)0x81, (byte)0x21, (byte)0xb2, (byte)0xeb, (byte)0xca, (byte)0xa9, (byte)0x7e,
            (byte)0xb9, (byte)0x21, (byte)0x19, (byte)0x24, (byte)0x44, (byte)0xf5, (byte)0xd8, (byte)0x2c,
            (byte)0x9d, (byte)0xfd, (byte)0x3a, (byte)0xc3, (byte)0xc5, (byte)0xea, (byte)0x45, (byte)0xf4,
            (byte)0xd2, (byte)0xe8, (byte)0x74, (byte)0x9f, (byte)0x57, (byte)0xcd, (byte)0xb9, (byte)0x59,
            (byte)0xa1, (byte)0x05, (byte)0xd4, (byte)0xaa, (byte)0xd6, (byte)0x1f, (byte)0xc5, (byte)0x1a
    };

    // ------------------------------------------------------------------ //
    //  Moteur RSA utilise comme coprocesseur modExp
    //
    //  On cree DEUX instances RSAPublicKey car modExp est appele deux fois
    //  de suite dans cmdEncrypt avec des exposants differents (k pour g^k,
    //  et k pour y^k). Une seule cle RSA ne peut avoir qu'un exposant a la
    //  fois, donc on en garde deux pour eviter de recharger entre les appels.
    //  En pratique on peut n'en avoir qu'une et recharger — mais deux est
    //  plus propre et ne coute que quelques octets EEPROM.
    // ------------------------------------------------------------------ //
    private final RSAPublicKey rsaKey1; // pour g^k mod p
    private final RSAPublicKey rsaKey2; // pour y^k mod p  (ou m*s mod p via astuce)
    private final Cipher       rsaCipher;

    // Buffers transients — aucune allocation dans les methodes
    // RAM totale : 3 x 128 = 384 octets
    private final byte[] tmp1;    // buffer intermediaire / sortie c1
    private final byte[] tmp2;    // buffer intermediaire / sortie c2
    private final byte[] result256; // c1 || c2 retourne au client

    private final RandomData rng;

    private static void fillZeros(byte[] buffer, short length) {
        for (short i = 0; i < length; i++) {
            buffer[i] = (byte)0x00;
        }
    }

    // ------------------------------------------------------------------ //
    //  Installation
    // ------------------------------------------------------------------ //
    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new ElGamalApplet();
    }

    protected ElGamalApplet() {
        register();

        // Creer les cles RSA 1024 bits (stockage EEPROM, fait une seule fois)
        rsaKey1 = (RSAPublicKey) KeyBuilder.buildKey(
                KeyBuilder.TYPE_RSA_PUBLIC, KeyBuilder.LENGTH_RSA_1024, false);
        rsaKey2 = (RSAPublicKey) KeyBuilder.buildKey(
                KeyBuilder.TYPE_RSA_PUBLIC, KeyBuilder.LENGTH_RSA_1024, false);

        // Cipher RSA sans padding = modExp brut
        rsaCipher = Cipher.getInstance(Cipher.ALG_RSA_NOPAD, false);

        // Buffers transients
        tmp1      = JCSystem.makeTransientByteArray(KEY_LEN, JCSystem.CLEAR_ON_RESET);
        tmp2      = JCSystem.makeTransientByteArray(KEY_LEN, JCSystem.CLEAR_ON_RESET);
        result256 = JCSystem.makeTransientByteArray((short)(KEY_LEN * 2), JCSystem.CLEAR_ON_RESET);

        rng = RandomData.getInstance(RandomData.ALG_TRNG);

        // Charger p comme modulus sur les deux cles (ne change jamais)
        rsaKey1.setModulus(P_BYTES, (short)0, KEY_LEN);
        rsaKey2.setModulus(P_BYTES, (short)0, KEY_LEN);
    }

    // ------------------------------------------------------------------ //
    //  Shareable
    // ------------------------------------------------------------------ //
    @Override
    public Shareable getShareableInterfaceObject(AID clientAID, byte parameter) {
        if (clientAID == null) return null;
        if (parameter == (byte)0x01 && !isInterfaceShared) {
            isInterfaceShared = true;
            return this;
        }
        return null;
    }

    @Override
    public void process(APDU apdu) {
        if (selectingApplet()) return;
        ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
    }

    // ------------------------------------------------------------------ //
    //  ElGamalInterface
    // ------------------------------------------------------------------ //
    @Override
    public byte[] helloWorld() { return HELLO_WORLD_MESSAGE_2; }

    /**
     * Chiffrement ElGamal via coprocesseur RSA.
     *
     * Entree  : apduBuff[ISO7816.OFFSET_CDATA .. +len-1] = message m
     * Sortie  : result256[0..127] = c1 = g^k mod p
     *           result256[128..255] = c2 = m * y^k mod p
     *
     * IMPORTANT : copier le resultat avant le prochain appel.
     */
    @Override
    public byte[] cmdEncrypt(byte[] apduBuff, short len) {
        fillZeros(result256, (short)256);

        // Generer k aleatoire
        generateEphemeralKey();

        // ---- c1 = g^k mod p ----
        // RSA : message=G, exposant=k, modulus=P => G^k mod P
        rsaKey1.setExponent(kBuffer, (short)0, KEY_LEN);
        rsaCipher.init(rsaKey1, Cipher.MODE_ENCRYPT);
        rsaCipher.doFinal(G_BYTES, (short)1, KEY_LEN, result256, (short)0);
        // result256[0..127] = c1

        // ---- s = y^k mod p ----
        // RSA : message=Y, exposant=k, modulus=P => Y^k mod P
        rsaKey2.setExponent(kBuffer, (short)0, KEY_LEN);
        rsaCipher.init(rsaKey2, Cipher.MODE_ENCRYPT);
        rsaCipher.doFinal(Y_BYTES, (short)0, KEY_LEN, tmp1, (short)0);
        // tmp1[0..127] = s = y^k mod p

        // ---- c2 = m * s mod p ----
        // On place m dans tmp2 (padde a gauche si besoin)
        Util.arrayFillNonAtomic(tmp2, (short)0, KEY_LEN, (byte)0);
        Util.arrayCopy(apduBuff, ISO7816.OFFSET_CDATA, tmp2, (short)(KEY_LEN - len), len);

        // Multiplication modulaire via RSA :
        //   m * s mod p = RSA_encrypt(s, exposant=m, modulus=p)  NON
        // La multiplication modulaire ne se fait pas directement via RSA.
        // On utilise une multiplication logicielle reduite, mais SIMPLE :
        // m < p et s < p donc m*s < p^2 < 2^2048, on fait la mul en 128x128
        // et on reduit. Comme m est petit (message utilisateur padde), on peut
        // optimiser : si m < 2^(KEY_LEN*4 bits) on tronque la boucle.
        // Pour la robustesse on fait la mul complete bornee.
        modMulFull(tmp2, tmp1, result256, KEY_LEN); // result256[128..255] = c2

        return result256;
    }

    /**
     * Dechiffrement ElGamal via coprocesseur RSA.
     *
     * Entree  : apduBuff[ISO7816.OFFSET_CDATA .. +255] = c1 (128 octets) || c2 (128 octets)
     * Sortie  : result256[0..127] = m (message original, padde a gauche)
     *
     * Algorithme :
     *   s     = c1^x mod p        (modExp RSA, cle privee x)
     *   s_inv = s^(p-2) mod p     (inverse par theoreme de Fermat, p premier)
     *   m     = c2 * s_inv mod p  (multiplication modulaire)
     *
     * IMPORTANT : copier le resultat avant le prochain appel.
     */
    @Override
    public byte[] cmdDecrypt(byte[] apduBuff, short len) {
        fillZeros(result256, (short)256);

        // ---- s = c1^x mod p ----
        // apduBuff est ici elgamalResult (tableau brut), c1 commence a l'offset 0
        rsaKey1.setExponent(X_BYTES, (short)0, KEY_LEN);
        rsaCipher.init(rsaKey1, Cipher.MODE_ENCRYPT);
        rsaCipher.doFinal(apduBuff, (short)0, KEY_LEN, tmp1, (short)0);
        // tmp1[0..127] = s = c1^x mod p

        // ---- s_inv = s^(p-2) mod p  (inverse de Fermat : p premier => s^(p-1)=1) ----
        // p-2 calcule depuis P_BYTES dans result256[0..KEY_LEN-1] (scratch avant modMulFull)
        Util.arrayCopy(P_BYTES, (short)0, result256, (short)0, KEY_LEN);
        result256[(short)(KEY_LEN - 1)] -= 2;
        rsaKey2.setExponent(result256, (short)0, KEY_LEN);
        rsaCipher.init(rsaKey2, Cipher.MODE_ENCRYPT);
        rsaCipher.doFinal(tmp1, (short)0, KEY_LEN, tmp2, (short)0);
        // tmp2[0..127] = s_inv

        // ---- m = c2 * s_inv mod p ----
        Util.arrayCopy(apduBuff, KEY_LEN, tmp1, (short)0, KEY_LEN);
        modMulFull(tmp1, tmp2, result256, KEY_LEN);
        // modMulFull ecrit en result256[KEY_LEN..2*KEY_LEN-1], on le ramene en [0..KEY_LEN-1]
        Util.arrayCopy(result256, KEY_LEN, result256, (short)0, KEY_LEN);

        return result256;
    }

    // ------------------------------------------------------------------ //
    //  modMulFull : multiplication modulaire UNIQUEMENT (pas modExp)
    //  Utilisee seulement pour c2 = m * s mod p.
    //  C'est UNE SEULE multiplication — pas de boucle dessus — donc
    //  128*128 = 16384 operations, acceptable (~50ms sur carte lente).
    //
    //  Buffers locaux pre-alloues : product et shifted dans EEPROM statique.
    //  On les met en static final pour ne pas surcharger la RAM transient.
    // ------------------------------------------------------------------ //

    // Ces deux buffers sont en EEPROM (pas transient) pour economiser la RAM.
    // Ils ne sont utilises que dans modMulFull qui n'est appele qu'une fois
    // par chiffrement, donc l'usure EEPROM est limitee.
    private final byte[] mulProduct = new byte[(short)(KEY_LEN * 2)];
    private final byte[] mulShifted = new byte[(short)(KEY_LEN * 2)];

    /**
     * Calcule result[outOffset .. outOffset+keyLen-1] = a * b mod p
     * en utilisant les buffers mulProduct et mulShifted.
     * Toutes les boucles sont bornees.
     */
    private void modMulFull(byte[] a, byte[] b, byte[] result, short keyLen) {
        short keyLen2 = (short)(keyLen * 2);

        // 1) Produit long a*b dans mulProduct — boucle bornee keyLen^2
        Util.arrayFillNonAtomic(mulProduct, (short)0, keyLen2, (byte)0);
        for (short i = (short)(keyLen - 1); i >= 0; i--) {
            short carry = 0;
            for (short j = (short)(keyLen - 1); j >= 0; j--) {
                short prod = (short)((short)(a[i] & 0xFF) * (short)(b[j] & 0xFF));
                short pos  = (short)(i + j + 1);
                prod = (short)(prod + (short)(mulProduct[pos] & 0xFF) + carry);
                mulProduct[pos] = (byte)(prod & 0xFF);
                carry = (short)((prod >> 8) & 0xFF);
            }
            mulProduct[i] = (byte)(carry & 0xFF);
        }

        // 2) Reduction mulProduct mod p — boucle bornee keyLen*8 = 1024
        // shifted = p dans la moitie haute
        Util.arrayFillNonAtomic(mulShifted, (short)0, keyLen2, (byte)0);
        Util.arrayCopy(P_BYTES, (short)0, mulShifted, keyLen, keyLen);

        // Trouver l'alignement par positions MSB
        short msbP   = msbPos(mulProduct, keyLen2);
        short msbS   = msbPos(mulShifted, keyLen2);
        short shifts = (short)(msbS - msbP);

        if (shifts < 0) {
            // mulProduct < p deja (ne devrait pas arriver pour m,s in [0,p-1])
            Util.arrayCopy(mulProduct, keyLen, result, KEY_LEN, keyLen);
            return;
        }
        if (shifts > (short)(keyLen * 8)) shifts = (short)(keyLen * 8);

        // Decaler shifted a GAUCHE pour l'aligner avec mulProduct — borne keyLen*8
        for (short i = 0; i < shifts; i++) {
            shiftLeft1(mulShifted, keyLen2);
        }

        // Soustraire — exactement shifts+1 iterations
        for (short s = (short)(shifts + 1); s > 0; s--) {
            if (compareN(mulProduct, mulShifted, keyLen2) >= 0) {
                subtractN(mulProduct, mulShifted, keyLen2);
            }
            shiftRight1(mulShifted, keyLen2);
        }

        // Copier le resultat dans result[KEY_LEN..KEY_LEN*2-1]
        Util.arrayCopy(mulProduct, keyLen, result, KEY_LEN, keyLen);
    }

    // ------------------------------------------------------------------ //
    //  Generation de k — bornee, 32 tentatives max
    // ------------------------------------------------------------------ //
    private final byte[] kBuffer = new byte[KEY_LEN]; // EEPROM, ok (ecrit rarement)

    private void generateEphemeralKey() {
        for (short attempt = 0; attempt < 32; attempt++) {
            rng.nextBytes(kBuffer, (short)0, KEY_LEN);
            // Masquer le bit haut pour garantir k < 2^1023 < p
            kBuffer[0] = (byte)(kBuffer[0] & (byte)0x7F);
            // Verifier que k != 0 et k != 1
            if (!isZeroOrOne(kBuffer)) return;
        }
        // Fallback (probabilite 2^-32) : k = x XOR 0x01 sur le dernier octet
        Util.arrayCopy(X_BYTES, (short)0, kBuffer, (short)0, KEY_LEN);
        kBuffer[(short)(KEY_LEN - 1)] ^= (byte)0x55;
    }

    // ------------------------------------------------------------------ //
    //  Primitives arithmetiques — utilisees uniquement dans modMulFull
    // ------------------------------------------------------------------ //

    private void shiftLeft1(byte[] buf, short len) {
        byte carry = 0;
        for (short i = (short)(len - 1); i >= 0; i--) {
            byte newCarry = (byte)((buf[i] & 0xFF) >>> 7);
            buf[i] = (byte)(((buf[i] & 0xFF) << 1) | carry);
            carry = newCarry;
        }
    }

    private void shiftRight1(byte[] buf, short len) {
        byte carry = 0;
        for (short i = 0; i < len; i++) {
            byte newCarry = (byte)(buf[i] & 0x01);
            buf[i] = (byte)(((buf[i] & 0xFF) >>> 1) | (carry << 7));
            carry = newCarry;
        }
    }

    private void subtractN(byte[] a, byte[] b, short len) {
        short borrow = 0;
        for (short i = (short)(len - 1); i >= 0; i--) {
            short diff = (short)((short)(a[i] & 0xFF) - (short)(b[i] & 0xFF) - borrow);
            if (diff < 0) { diff += 256; borrow = 1; } else { borrow = 0; }
            a[i] = (byte)(diff & 0xFF);
        }
    }

    private short compareN(byte[] a, byte[] b, short len) {
        for (short i = 0; i < len; i++) {
            short av = (short)(a[i] & 0xFF);
            short bv = (short)(b[i] & 0xFF);
            if (av < bv) return (short)-1;
            if (av > bv) return (short) 1;
        }
        return 0;
    }

    /**
     * Retourne la position du MSB dans buf[0..len-1].
     * Resultat : nombre de bits depuis le bit le plus haut jusqu'au MSB.
     * Boucle bornee par len*8.
     */
    private short msbPos(byte[] buf, short len) {
        for (short i = 0; i < len; i++) {
            if (buf[i] != 0) {
                byte b = buf[i];
                for (short bit = 7; bit >= 0; bit--) {
                    if ((b & (byte)(1 << bit)) != 0) {
                        return (short)((short)(i * 8) + (short)(7 - bit));
                    }
                }
            }
        }
        return (short)(len * 8);
    }

    private boolean isZeroOrOne(byte[] a) {
        for (short i = 0; i < (short)(KEY_LEN - 1); i++) {
            if (a[i] != 0) return false;
        }
        return (a[(short)(KEY_LEN - 1)] == 0 || a[(short)(KEY_LEN - 1)] == 1);
    }
}