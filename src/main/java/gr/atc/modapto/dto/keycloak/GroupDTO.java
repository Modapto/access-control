package gr.atc.modapto.dto.keycloak;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class GroupDTO {
    private String id;
    private String name;
    private String path;
    private int subGroupCount;
    private List<String> subGroups;
}
