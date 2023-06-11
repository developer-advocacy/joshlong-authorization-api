package com.joshlong;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.actuate.autoconfigure.security.servlet.EndpointRequest;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.firewall.DefaultHttpFirewall;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;
import org.springframework.util.Assert;

import java.util.Arrays;
import java.util.stream.Stream;

/**
 * Provides the centralized OAuth authorization service for all my infrastructure going forward.
 *
 * @author Josh Long
 */
@EnableConfigurationProperties(AuthorizationApiProperties.class)
@SpringBootApplication
public class AuthorizationApiApplication {

    private final static Logger log = LoggerFactory.getLogger(AuthorizationApiApplication.class);

    public static void main(String[] args) {
        SpringApplication.run(AuthorizationApiApplication.class, args);
    }

/*
    @Bean
    WebSecurityCustomizer webSecurityCustomizer() {
        return web -> {
            log.info("installing the " + DefaultHttpFirewall.class.getName());
            web.httpFirewall(new DefaultHttpFirewall());
        };
    }
*/

    @Bean
    @Order(1)
    SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http)
            throws Exception {

        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
        http.getConfigurer(OAuth2AuthorizationServerConfigurer.class).oidc(Customizer.withDefaults()); // Enable OpenID Connect 1.0
        http
                // Redirect to the login page when not authenticated from the
                // authorization endpoint
                .exceptionHandling((exceptions) -> exceptions
                        .defaultAuthenticationEntryPointFor(
                                new LoginUrlAuthenticationEntryPoint("/login"),
                                new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
                        )
                )
                // Accept access tokens for User Info and/or Client Registration
                .oauth2ResourceServer((resourceServer) -> resourceServer
                        .jwt(Customizer.withDefaults()));

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
    InMemoryUserDetailsManager inMemoryUserDetailsManager(AuthorizationApiProperties properties) {
        Assert.state(properties.users() != null && properties.users().length > 0, "you must specify some users!");
        var users = Stream.of(properties.users())
                .peek(e -> log.info("registered new user [" + e.username() + "] with password [" + e.password() + "] and roles[" +
                                    Arrays.toString(e.roles()) + "]"))
                .map(e -> User.withDefaultPasswordEncoder()
                        .roles(e.roles())
                        .username(e.username())
                        .password(e.password())
                        .build()
                )
                .toList();
        return new InMemoryUserDetailsManager(users);
    }

}


@ConfigurationProperties(prefix = "bootiful.authorization")
record AuthorizationApiProperties(UserSpecification[] users) {
}

record UserSpecification(String password, String username, String[] roles) {
}