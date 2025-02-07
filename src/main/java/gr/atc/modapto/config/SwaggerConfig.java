package gr.atc.modapto.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.security.SecurityScheme;

@Configuration
public class SwaggerConfig {

  @Value("${build.version}")
  private String appVersion;

  @Bean
  public OpenAPI openAPIDocumentation() {
    return new OpenAPI()
        .info(new Info()
            .title("User Manager API")
            .version(appVersion)
            .description("API documentation for User Manager service"))
        .openapi("3.0.3")
        .components(new Components().addSecuritySchemes("bearerToken", new SecurityScheme()
            .type(SecurityScheme.Type.HTTP).scheme("bearer").bearerFormat("JWT")));
  }
}
