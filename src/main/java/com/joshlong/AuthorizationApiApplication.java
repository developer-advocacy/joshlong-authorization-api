package com.joshlong;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.aot.hint.RuntimeHints;
import org.springframework.aot.hint.RuntimeHintsRegistrar;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.actuate.autoconfigure.security.servlet.EndpointRequest;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ImportRuntimeHints;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.converter.RsaKeyConverters;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;

import javax.sql.DataSource;
import java.io.ByteArrayInputStream;
import java.util.*;
import java.util.stream.Stream;

/**
 * Provides the centralized OAuth authorization service for all my infrastructure going forward.
 *
 * @author Josh Long
 */
@EnableConfigurationProperties(AuthorizationApiProperties.class)
@SpringBootApplication
@ImportRuntimeHints(AuthorizationApiApplication.AotConfiguration.class)
public class AuthorizationApiApplication {

    static class AotConfiguration
            implements RuntimeHintsRegistrar {

        @Override
        public void registerHints(RuntimeHints hints, ClassLoader classLoader) {
            Set.of("data", "schema").forEach(folder -> hints.resources().registerPattern("sql/" + folder + "/*sql"));
        }
    }

    private final static Logger log = LoggerFactory.getLogger(AuthorizationApiApplication.class);

    public static void main(String[] args) {
        SpringApplication.run(AuthorizationApiApplication.class, args);
    }

    @Bean
    @Order(1)
    SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http)
            throws Exception {

        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);

        http
                .getConfigurer(OAuth2AuthorizationServerConfigurer.class)
                .oidc(Customizer.withDefaults()); // Enable OpenID Connect 1.0

        http
                // Redirect to the login page when not authenticated from the authorization endpoint
                .exceptionHandling((exceptions) -> exceptions
                        .defaultAuthenticationEntryPointFor(
                                new LoginUrlAuthenticationEntryPoint("/login"),
                                new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
                        )
                )
                // Accept access tokens for User Info and/or Client Registration
                .oauth2ResourceServer((rs) -> rs.jwt(Customizer.withDefaults()));

        return http.build();
    }

    @Bean
    @Order(2)
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests((authorize) -> authorize
                        .requestMatchers(EndpointRequest.toAnyEndpoint()).permitAll()
                        .anyRequest().authenticated()
                )
                .formLogin(Customizer.withDefaults());

        return http.build();
    }

    @Bean
    JdbcUserDetailsManager jdbcUserDetailsManager(DataSource dataSource) {
        return new JdbcUserDetailsManager(dataSource);
    }

    @Bean
    ApplicationRunner usersInitializationRunner(
            PasswordEncoder passwordEncoder,
            AuthorizationApiProperties properties,
            UserDetailsManager userDetailsManager) {
        return args -> Stream.of(properties.users())
                .peek(e -> log.info("registered new user [" + e.username() + "] with password [" + e.password() + "] and roles[" +
                                    Arrays.toString(e.roles()) + "]"))
                .map(e -> User
                        .builder()
                        .passwordEncoder(passwordEncoder::encode)
                        .roles(e.roles())
                        .username(e.username())
                        .password(e.password())
                        .build()
                )
                .filter(u -> !userDetailsManager.userExists(u.getUsername()))
                .forEach(userDetailsManager::createUser);
    }

    @Bean
    PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    @Bean
    JdbcOAuth2AuthorizationConsentService jdbcOAuth2AuthorizationConsentService(
            JdbcOperations jdbcOperations, RegisteredClientRepository repository) {
        return new JdbcOAuth2AuthorizationConsentService(jdbcOperations, repository);
    }

    @Bean
    JdbcOAuth2AuthorizationService jdbcOAuth2AuthorizationService(
            JdbcOperations jdbcOperations, RegisteredClientRepository rcr) {
        return new JdbcOAuth2AuthorizationService(jdbcOperations, rcr);
    }

    @Bean
    JWKSource<SecurityContext> jwkSource(
            @Value("${jwk.key.id:bootiful-jwk-id}") String id,
            @Value("${jwk.key.public}") String publicKeyBase64Encoded,
            @Value("${jwk.key.private}") String privateKeyBase64Encoded
    ) throws Exception {

        var decoder = Base64.getDecoder();
        var publicKey = decoder.decode(publicKeyBase64Encoded);
        var privateKey = decoder.decode(privateKeyBase64Encoded);

        try (
                var publicKeyInputStream = new ByteArrayInputStream(publicKey);
                var privateKeyInputStream = new ByteArrayInputStream(privateKey)
        ) {
            var rsaPrivateKey = RsaKeyConverters.pkcs8().convert(privateKeyInputStream);
            var rsaPublicKey = RsaKeyConverters.x509().convert(publicKeyInputStream);
            var rsa = new RSAKey.Builder(rsaPublicKey)
                    .privateKey(rsaPrivateKey)
                    .keyID(id)
                    .build();
            var jwk = new JWKSet(rsa);
            return new ImmutableJWKSet<>(jwk);
        }
    }

    @Bean
    RegisteredClientRepository registeredClientRepository(JdbcTemplate template) {
        return new JdbcRegisteredClientRepository(template);
    }

    @Bean
    ApplicationRunner clientsRunner(RegisteredClientRepository repository,
                                    @Value("${TWIS_CLIENT_REDIRECT_URI:http://127.0.0.1:8082/login/oauth2/code/spring}") String twisRedirectUri,
                                    @Value("${TWIS_CLIENT_KEY_SECRET}") String twisClientSecret,
                                    @Value("${SOCIALHUB_JOSHLONG_CLIENT_KEY_SECRET}") String socialHubClientSecret) {
        return args -> {
            var clients = Map.of(

                    "socialhub-joshlong", RegisteredClient
                            .withId(UUID.randomUUID().toString())
                            .clientSecret((socialHubClientSecret))
                            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                            .authorizationGrantTypes(grantTypes -> grantTypes.add(
                                    AuthorizationGrantType.CLIENT_CREDENTIALS))
                            .scopes(scopes -> scopes.addAll(Set.of("user.read", "user.write", OidcScopes.OPENID)))
                    ,
                    "twis", RegisteredClient
                            .withId(UUID.randomUUID().toString())
                            .clientSettings(ClientSettings.builder()
                                    .requireAuthorizationConsent(true)
                                    .build())
                            .clientSecret((twisClientSecret))
                            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                            .authorizationGrantTypes(grantTypes -> grantTypes.addAll(Set.of(
                                    AuthorizationGrantType.CLIENT_CREDENTIALS,
                                    AuthorizationGrantType.AUTHORIZATION_CODE,
                                    AuthorizationGrantType.REFRESH_TOKEN)))
                            .redirectUri(twisRedirectUri)
                            .scopes(scopes -> scopes.addAll(Set.of("user.read", "user.write", OidcScopes.OPENID)))
            );
            clients.forEach((clientId, rcb) -> {
                if (repository.findByClientId(clientId) == null)
                    repository.save(rcb.clientId(clientId).build());
            });
        };
    }
}


@ConfigurationProperties(prefix = "bootiful.authorization")
record AuthorizationApiProperties(UserSpecification[] users) {
}

record UserSpecification(String password, String username, String[] roles) {
}
