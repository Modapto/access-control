package gr.atc.modapto;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;

@SpringBootApplication
@EnableMethodSecurity
@EnableScheduling
public class ModaptoUserManagerApplication {

	public static void main(String[] args) {
		SpringApplication.run(ModaptoUserManagerApplication.class, args);
	}

}
