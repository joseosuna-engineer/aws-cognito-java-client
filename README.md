# README #

### About ###

Amazon Cognito lets you add user sign-up, sign-in, and access control to your web and mobile apps quickly and easily. Amazon Cognito scales to millions of users and supports sign-in with social identity providers, such as Facebook, Google, and Amazon, and enterprise identity providers via SAML 2.0.

* Java client to connect to AWS Cognito.


### How to ###


~~~~
         @Autowired
    private CognitoHelper cognitoHelper;  

  

        cognitoHelper.init(
                request.getPoolId(),
                request.getClientAppId(),
                request.getRegion()
        );

        String jwtTokek = cognitoHelper.auth(
                request.getUsername(),
                request.getPassword()
        );

       
~~~~
