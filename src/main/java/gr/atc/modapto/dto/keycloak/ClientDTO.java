package gr.atc.modapto.dto.keycloak;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class ClientDTO {
    private String id;
    private String clientId;
    private String name;
    private boolean enabled;
    private String baseUrl;
}
