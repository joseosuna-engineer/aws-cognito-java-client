package com.prottonne.cognito;

import com.prottonne.cognito.exception.CognitoException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

/**
 * The CognitoHelper class abstracts the functionality of connecting to the
 * Cognito user pool and Federated Identities.
 */
@Component
public class CognitoHelper {

    private final Logger logger = LoggerFactory.getLogger(this.getClass());

    private String poolId;
    private String clientAppId;
    private String region;

    @Autowired
    private AuthenticationHelper authenticationHelper;

    public CognitoHelper() {
        super();
    }

    public void init(String poolId, String clientAppId,
            String region) {
        this.poolId = poolId;
        this.clientAppId = clientAppId;
        this.region = region;
    }

    /**
     * Helper method to validate the user
     *
     * @param username represents the username in the cognito user pool
     * @param password represents the password in the cognito user pool
     * @return returns the JWT token after the validation
     */
    public String auth(String username, String password) {
        authenticationHelper.init(poolId, clientAppId, region);

        logger.info("username={}", username);
        try {
            return authenticationHelper.
                    initPerformSRPAuthentication(username, password);
        } catch (Exception ex) {
            throw new CognitoException(ex);
        }
    }

}
