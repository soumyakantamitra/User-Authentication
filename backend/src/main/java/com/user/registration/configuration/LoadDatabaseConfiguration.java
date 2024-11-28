package com.user.registration.configuration;

import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import com.user.registration.features.authentication.model.AuthenticationUser;
import com.user.registration.features.authentication.repository.AuthenticationUserRepository;
import com.user.registration.features.authentication.utils.Encoder;

@Configuration
public class LoadDatabaseConfiguration {
    private final Encoder encoder;
    

    public LoadDatabaseConfiguration(Encoder encoder) {
        this.encoder = encoder;
    }


    @Bean
    public CommandLineRunner initDatabase(AuthenticationUserRepository authenticationUserRepository) {

        return args -> {
            AuthenticationUser authenticationUser = new AuthenticationUser("blavla@gmail.com", encoder.encode("okay"));
            authenticationUserRepository.save(authenticationUser);
        };
    }

}
