package com.joshlong;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

/**
 * Provides the centralized OAuth authorization service for all my infrastructure going forward.
 *
 * @author Josh Long
 */
@SpringBootApplication
public class AuthorizationServerApplication {

    public static void main(String[] args) {
        SpringApplication.run(AuthorizationServerApplication.class, args);
    }

    // todo refactor this to talk to a SQL db or something.
    //  Puuuhleeze don't just leave the keys to the kingdom laying around in the Java code!
    @Bean
    InMemoryUserDetailsManager inMemoryUserDetailsManager() {
        var one = User.withDefaultPasswordEncoder().roles("admin").username("sjohnr").password("pw").build();
        var two = User.withDefaultPasswordEncoder().roles("user").username("jlong").password("pw").build();
        return new InMemoryUserDetailsManager(one, two);
    }
}

