package gr.atc.modapto.dto.keycloak;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class ClientRoleDTO {
    private String id;
    private String name;
    private String description;
    private boolean composite;
    private boolean clientRole;
}
