package com.joshlong;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Provides the centralized OAuth authorization service for all my infrastructure going forward.
 *
 * @author Josh Long
 */
@SpringBootApplication
public class AuthorizationApiApplication {

    public static void main(String[] args) {
        SpringApplication.run(AuthorizationApiApplication.class, args);
    }

    //todo figure out how to UNSECURE the actuator endpoints so that kubernetes can health check the container!!
    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity security) throws Exception {
        security.authorizeHttpRequests(a -> a.requestMatchers("/actuator/health/**").permitAll());
        return security.build() ;
    }

    @Bean
    InMemoryUserDetailsManager inMemoryUserDetailsManager() {
        var one = User.withDefaultPasswordEncoder().roles("admin").username("sjohnr").password("pw").build();
        var two = User.withDefaultPasswordEncoder().roles("user").username("jlong").password("pw").build();
        return new InMemoryUserDetailsManager(one, two);
    }
}

