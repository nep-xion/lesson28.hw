import org.junit.Test;
import org.junit.BeforeClass;
import org.junit.Assert;

import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.Signature;
import java.security.InvalidKeyException;
import java.security.SignatureException;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class MaxFeeTxHandlerTest {
    private static final int NUM_KEYS = 2;

    private static PublicKey[] publicKeys;
    private static PrivateKey[] privateKeys;

    @BeforeClass public static void beforeClass() throws NoSuchAlgorithmException, NoSuchProviderException {
        Security.addProvider(new BouncyCastleProvider());

        publicKeys = new PublicKey[NUM_KEYS];
        privateKeys = new PrivateKey[NUM_KEYS];

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG");

        keyGen.initialize(512, random);

        for (int i = 0; i < NUM_KEYS; ++i) {
            KeyPair pair = keyGen.generateKeyPair();
            publicKeys[i] = pair.getPublic();
            privateKeys[i] = pair.getPrivate();
        }
    }

    @Test public void testIsValidTxSuccess() throws NoSuchAlgorithmException, InvalidKeyExcep