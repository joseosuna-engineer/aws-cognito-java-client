package com.prottonne.cognito;

import com.prottonne.cognito.util.Hkdf;
import com.amazonaws.auth.AWSStaticCredentialsProvider;
import com.amazonaws.auth.AnonymousAWSCredentials;
import com.amazonaws.regions.Regions;
import com.amazonaws.services.cognitoidp.AWSCognitoIdentityProvider;
import com.amazonaws.services.cognitoidp.AWSCognitoIdentityProviderClientBuilder;
import com.amazonaws.services.cognitoidp.model.AuthFlowType;
import com.amazonaws.services.cognitoidp.model.ChallengeNameType;
import com.amazonaws.services.cognitoidp.model.InitiateAuthRequest;
import com.amazonaws.services.cognitoidp.model.InitiateAuthResult;
import com.amazonaws.services.cognitoidp.model.RespondToAuthChallengeRequest;
import com.amazonaws.services.cognitoidp.model.RespondToAuthChallengeResult;
import com.amazonaws.util.Base64;
import com.amazonaws.util.StringUtils;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;
import java.util.Map;
import java.util.SimpleTimeZone;
import java.util.concurrent.ConcurrentHashMap;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

/**
 * Private class for SRP client side math.
 */
@Component
public class AuthenticationHelper {



    private static final String HEX_N
            = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
            + "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
            + "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
            + "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
            + "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
            + "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
            + "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
            + "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
            + "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
            + "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
            + "15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64"
            + "ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7"
            + "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B"
            + "F12FFA06D98A0864D87602733EC86A64521F2B18177B200C"
            + "BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31"
            + "43DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF";
    private static final int SIXTEEN = 16;
    private static final BigInteger N = new BigInteger(HEX_N, SIXTEEN);
    private static final int TWO = 2;
    private static final BigInteger G_LOWER = BigInteger.valueOf(TWO);
    private static final BigInteger K_LOWER;
    private static final int EPHEMERAL_KEY_LENGTH = 1024;
    private static final int DERIVED_KEY_SIZE = SIXTEEN;
    private static final String DERIVED_KEY_INFO = "Caldera Derived Key";
    private static final String HMACSHA256 = "HmacSHA256";
    private static final String USERNAME_TAG = "USERNAME";
    private static final ThreadLocal<MessageDigest> THREAD_MESSAGE_DIGEST
            = getThreadMessageDigest();
    private static final SecureRandom SECURE_RANDOM;
    private static final int ONE = 1;

    static {
        try {
            SECURE_RANDOM = SecureRandom.getInstance("SHA1PRNG");

            MessageDigest messageDigest = THREAD_MESSAGE_DIGEST.get();
            messageDigest.reset();
            messageDigest.update(N.toByteArray());
            byte[] digest = messageDigest.digest(G_LOWER.toByteArray());
            K_LOWER = new BigInteger(ONE, digest);
        } catch (NoSuchAlgorithmException e) {
            throw new SecurityException(e.getMessage(), e);
        }
    }

    private BigInteger aLower;
    private BigInteger aUpper;
    private String userPoolID;
    private String clientId;
    private String region;

    @Autowired
    private Hkdf hkdf;

    public AuthenticationHelper() {

        do {
            aLower
                    = getLowerA();
            aUpper = G_LOWER.modPow(aLower, N);
        } while (aUpper.mod(N).equals(BigInteger.ZERO));

    }

    public void init(String userPoolID, String clientid, String region) {

     
        this.userPoolID = userPoolID;
        this.clientId = clientid;
        this.region = region;
    }

    private static BigInteger getLowerA() {
        return new BigInteger(EPHEMERAL_KEY_LENGTH,
                SECURE_RANDOM).mod(N);
    }

    private static ThreadLocal<MessageDigest> getThreadMessageDigest() {
        return new ThreadLocal<MessageDigest>() {
            @Override
            protected MessageDigest initialValue() {
                try {
                    return MessageDigest.getInstance("SHA-256");
                } catch (NoSuchAlgorithmException e) {
                    throw new SecurityException("Exception in authentication",
                            e);
                }
            }
        };
    }

    private BigInteger getaUpper() {
        return aUpper;
    }

    public byte[] getPasswordAuthenticationKey(String userId,
            String userPassword,
            BigInteger bIntegerPaK,
            BigInteger salt) {

      

        MessageDigest messageDigest = THREAD_MESSAGE_DIGEST.get();
        messageDigest.reset();
        messageDigest.update(aUpper.toByteArray());
        BigInteger u = new BigInteger(ONE,
                messageDigest.digest(bIntegerPaK.toByteArray()));
        if (u.equals(BigInteger.ZERO)) {
            throw new SecurityException("Hash of A and B cannot be zero");
        }

        messageDigest.reset();

      

        messageDigest.update(this.userPoolID.split("_", TWO)[ONE].
                getBytes(StringUtils.UTF8));
        messageDigest.update(userId.getBytes(StringUtils.UTF8));
        messageDigest.update(":".getBytes(StringUtils.UTF8));

  

        byte[] userIdHash = messageDigest.
                digest(userPassword.getBytes(StringUtils.UTF8));
        messageDigest.reset();
        messageDigest.update(salt.toByteArray());
        BigInteger x = new BigInteger(ONE, messageDigest.digest(userIdHash));
        BigInteger sIntegerPaK = (bIntegerPaK.subtract(
                K_LOWER.multiply(G_LOWER.modPow(x, N))).
                modPow(aLower.add(u.multiply(x)), N)).mod(N);

  

        hkdf.init(sIntegerPaK.toByteArray(), u.toByteArray());
        return hkdf.deriveKey(DERIVED_KEY_INFO, DERIVED_KEY_SIZE);

    }

    /**
     * Method to orchestrate the SRP Authentication
     *
     * @param username Username for the SRP request
     * @param password Password for the SRP request
     * @return the JWT token if the request is successful else null.
     */
    String initPerformSRPAuthentication(String username, String password)
            throws NoSuchAlgorithmException, InvalidKeyException,
            UnsupportedEncodingException {



        String authresult = null;

        InitiateAuthRequest initiateAuthRequest
                = initiateUserSrpAuthRequest(username);

        AnonymousAWSCredentials awsCreds = new AnonymousAWSCredentials();
        AWSCognitoIdentityProvider cognitoIdentityProvider
                = AWSCognitoIdentityProviderClientBuilder.
                        standard().
                        withCredentials(
                                new AWSStaticCredentialsProvider(awsCreds)).
                        withRegion(Regions.fromName(this.region)).
                        build();



        InitiateAuthResult initiateAuthResult
                = cognitoIdentityProvider.initiateAuth(initiateAuthRequest);

      

        if (ChallengeNameType.PASSWORD_VERIFIER.toString().
                equals(initiateAuthResult.getChallengeName())) {
            RespondToAuthChallengeRequest challengeRequest
                    = userSrpAuthRequest(initiateAuthResult, password);
            RespondToAuthChallengeResult result
                    = cognitoIdentityProvider.
                            respondToAuthChallenge(challengeRequest);

        
            authresult = result.getAuthenticationResult().getIdToken();
        }

        return authresult;
    }

    /**
     * Initialize the authentication request for the first time.
     *
     * @param username The user for which the authentication request is created.
     * @return the Authentication request.
     */
    private InitiateAuthRequest initiateUserSrpAuthRequest(String username) {

    

        InitiateAuthRequest initiateAuthRequest = new InitiateAuthRequest();
        initiateAuthRequest.setAuthFlow(AuthFlowType.USER_SRP_AUTH);
        initiateAuthRequest.setClientId(this.clientId);

  

        initiateAuthRequest.addAuthParametersEntry(USERNAME_TAG, username);
        initiateAuthRequest.addAuthParametersEntry("SRP_A",
                this.getaUpper().toString(SIXTEEN));

     

        return initiateAuthRequest;
    }

    public RespondToAuthChallengeRequest userSrpAuthRequest(
            InitiateAuthResult challenge,
            String password
    ) throws NoSuchAlgorithmException, InvalidKeyException {

        String userIdForSRP = challenge.
                getChallengeParameters().get("USER_ID_FOR_SRP");
        String usernameInternal = challenge.
                getChallengeParameters().get(USERNAME_TAG);

    

        BigInteger bIntegerUaR = new BigInteger(
                challenge.getChallengeParameters().get("SRP_B"), SIXTEEN);
        if (bIntegerUaR.mod(AuthenticationHelper.N).equals(BigInteger.ZERO)) {
            throw new SecurityException("SRP error, B cannot be zero");
        }

        BigInteger salt = new BigInteger(challenge.
                getChallengeParameters().get("SALT"), SIXTEEN);
        byte[] key = getPasswordAuthenticationKey(userIdForSRP,
                password, bIntegerUaR, salt);

  

        Mac mac = Mac.getInstance(HMACSHA256);
        SecretKeySpec keySpec = new SecretKeySpec(key, HMACSHA256);
        mac.init(keySpec);
        mac.update(this.userPoolID.split("_", TWO)[ONE].
                getBytes(StringUtils.UTF8));
        mac.update(userIdForSRP.getBytes(StringUtils.UTF8));
        byte[] secretBlock = Base64.decode(challenge.
                getChallengeParameters().get("SECRET_BLOCK"));
        mac.update(secretBlock);
        SimpleDateFormat simpleDateFormat
                = new SimpleDateFormat("EEE MMM d HH:mm:ss z yyyy", Locale.US);
        simpleDateFormat.setTimeZone(
                new SimpleTimeZone(SimpleTimeZone.UTC_TIME, "UTC"));
        Date timestamp = new Date();
        String dateString = simpleDateFormat.format(timestamp);
        byte[] dateBytes = dateString.getBytes(StringUtils.UTF8);
        byte[] hmac = null;
        hmac = mac.doFinal(dateBytes);

        SimpleDateFormat formatTimestamp
                = new SimpleDateFormat("EEE MMM d HH:mm:ss z yyyy", Locale.US);
        formatTimestamp.setTimeZone(
                new SimpleTimeZone(SimpleTimeZone.UTC_TIME, "UTC"));

        Map<String, String> srpAuthResponses = new ConcurrentHashMap<>();
        srpAuthResponses.put("PASSWORD_CLAIM_SECRET_BLOCK",
                challenge.getChallengeParameters().get("SECRET_BLOCK"));
        srpAuthResponses.put("PASSWORD_CLAIM_SIGNATURE",
                new String(Base64.encode(hmac), StringUtils.UTF8));
        srpAuthResponses.put("TIMESTAMP", formatTimestamp.format(timestamp));
        srpAuthResponses.put(USERNAME_TAG, usernameInternal);

    

        RespondToAuthChallengeRequest authChallengeRequest
                = new RespondToAuthChallengeRequest();
        authChallengeRequest.setChallengeName(challenge.getChallengeName());



        authChallengeRequest.setClientId(clientId);
        authChallengeRequest.setSession(challenge.getSession());
        authChallengeRequest.setChallengeResponses(srpAuthResponses);

        return authChallengeRequest;
    }

}
