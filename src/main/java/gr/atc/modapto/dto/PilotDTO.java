package gr.atc.modapto.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import gr.atc.modapto.enums.PilotRole;
import jakarta.validation.constraints.NotEmpty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class PilotDTO {

    @NotEmpty
    @JsonProperty("name")
    private String name;

    @JsonProperty("subGroups")
    private List<PilotRole> subGroups;
}
