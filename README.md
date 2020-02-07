# README #

### About ###

* Java client to connect to AWS Cognito.


### How to ###

* add dependency pom.xml
~~~~
        <!-- Cognito -->
        <dependency>
            <groupId>com.prottonne</groupId>
            <artifactId>cognito-my-library</artifactId>
            <version>0.1.0</version>
        </dependency>
~~~~

* add Beans to @SpringBootApplication File:
~~~~
    @Bean
    public AutenticaCognito autenticaCognito() {
        return new AutenticaCognito();
    }

    @Bean
    public CognitoHelper cognitoHelper() {
        return new CognitoHelper();
    }

    @Bean
    public AuthenticationHelper authenticationHelper() {
        return new AuthenticationHelper();
    }

    @Bean
    public Hkdf hkdf() {
        return new Hkdf();
    }
~~~~
* Inyect Bean:
~~~~
    @Autowired
    private AutenticaCognito autenticaCognito;

    String tokenJWTcognito
                    = autenticaCognito.autenticarUsuario(getPeticionCognito(
                            user, peticion.getPass()
                    ));
~~~~
