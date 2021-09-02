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

    @Test public void testIsValidTxSuccess() throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        // Initialize pool with one UTXO that belongs to address0 / scrooge {@code publicKeys[0]}
        UTXOPool pool = new UTXOPool();

        // Create initial transaction that creates 100 coin signed by scrooge {@code publicKeys[0]}
        Transaction transaction0 = new Transaction();
        transaction0.addInput(null, 0);
        transaction0.addOutput(100.0, publicKeys[0]);
        Transaction.Output out = transaction0.getOutput(0);
        transaction0.finalize();

        UTXO utxo = new UTXO(transaction0.getHash(), 0);
        pool.addUTXO(utxo, out);

        MaxFeeTxHandler txHandler = new MaxFeeTxHandler(pool);

        // Create transaction that gives 1 coin to address1 {@code publicKeys[1]}
        Transaction transaction = new Transaction();
        transaction.addInput(transaction0.getHash(), 0);
        transaction.addOutput(1.0, publicKeys[1]);
        Transaction.Input input = transaction.getInput(0);

        // Address0 needs to sign it so that the transaction is valid
        byte[] inputDataToSign = transaction.getRawDataToSign(0);
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initSign(privateKeys[0]);
        sig.update(inputDataToSign);
        byte[] signatureBytes = sig.sign();
        input.addS