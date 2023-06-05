package com.joshlong;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.actuate.autoconfigure.security.servlet.EndpointRequest;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;

import java.net.URL;
import java.util.Map;

import static org.springframework.security.core.userdetails.User.withDefaultPasswordEncoder;

/**
 * Provides the centralized OAuth authorization service for all my infrastructure going forward.
 *
 * @author Josh Long
 */
@EnableConfigurationProperties(AuthorizationApiProperties.class)
@SpringBootApplication
public class AuthorizationApiApplication {

    private final static Logger log = LoggerFactory.getLogger(AuthorizationApiApplication.class) ;

    public static void main(String[] args) {
        SpringApplication.run(AuthorizationApiApplication.class, args);
    }

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
        if (properties.users() != null) {
            if (log.isDebugEnabled()){
                log.debug("logging users that I hope to configure one day");
                properties.users().forEach((k, v) ->  log.debug( k + '=' + v));
            }
        }
        /*var users = new ConcurrentHashMap<String, UserDetails>();
        properties.users().forEach((userId, user) -> {
            var ud = new User(userId, user.getPassword(), true, true, true, true,
                    user.getRoles().stream()
                            .map(r -> new SimpleGrantedAuthority(r)).toList());
            users.put(userId, ud);
        }); //todo make the thing above work*/
        var one = withDefaultPasswordEncoder().roles("admin").username("sjohnr").password("pw").build();
        var two = withDefaultPasswordEncoder().roles("user").username("jlong").password("pw").build();
        return new InMemoryUserDetailsManager(one, two);
    }
}

// todo figure out how to make this secure and to not be stored in the source code!
@ConfigurationProperties(prefix = "bootiful.authorization")
record AuthorizationApiProperties(URL issuerUri, Map<String, SecurityProperties.User> users) {
}