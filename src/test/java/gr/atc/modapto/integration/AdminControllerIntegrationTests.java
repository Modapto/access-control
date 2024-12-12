package gr.atc.modapto.integration;

import gr.atc.modapto.controller.BaseResponse;
import gr.atc.modapto.controller.UserManagerController;
import gr.atc.modapto.dto.AuthenticationResponseDTO;
import gr.atc.modapto.dto.CredentialsDTO;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.*;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;


import static org.hamcrest.Matchers.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureMockMvc
@ActiveProfiles("local")
class AdminControllerIntegrationTests {

    @Autowired
    private UserManagerController userManagerController;

    @Autowired
    private MockMvc mockMvc;

    private String jwt;

    @BeforeEach
    void setup() {
        CredentialsDTO credentials = CredentialsDTO.builder()
                .email("test@test.com")
                .password("Test123@")
                .build();

        ResponseEntity<BaseResponse<AuthenticationResponseDTO>> response = userManagerController.authenticateOrRefreshToken(credentials, null);
        if (response != null && response.getBody() != null && response.getBody().getData() != null)
            jwt = response.getBody().getData().getAccessToken();
    }

    @DisplayName("Get All User Roles: Success")
    @Test
    void givenValidJwt_whenGetAllUserRoles_thenReturnUserRoles() throws Exception {
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(jwt);

        // When
        ResultActions response = mockMvc.perform(get("/api/admin/roles")
                .headers(headers)
                .contentType(MediaType.APPLICATION_JSON));

        // Then
        response.andDo(print())
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success", is(true)))
                .andExpect(jsonPath("$.message", is("User roles retrieved successfully")))
                .andExpect(jsonPath("$.data", hasItem("ADMIN")));
    }

    @DisplayName("Get All Pilot Codes: Success")
    @Test
    void givenValidJwt_whenGetAllPilotCodes_thenReturnPilotCodes() throws Exception {
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(jwt);

        // When
        ResultActions response = mockMvc.perform(get("/api/admin/pilots")
                .headers(headers)
                .contentType(MediaType.APPLICATION_JSON));

        // Then
        response.andDo(print())
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success", is(true)))
                .andExpect(jsonPath("$.message", is("Pilot codes retrieved successfully")))
                .andExpect(jsonPath("$.data", hasItem("CRF")));
    }

    @DisplayName("Get All Pilot Roles: Success")
    @Test
    void givenValidJwt_whenGetAllPilotRoles_thenReturnPilotRoles() throws Exception {
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(jwt);

        // When
        ResultActions response = mockMvc.perform(get("/api/admin/pilot-roles")
                .headers(headers)
                .contentType(MediaType.APPLICATION_JSON));

        // Then
        response.andDo(print())
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success", is(true)))
                .andExpect(jsonPath("$.message", is("Pilot roles retrieved successfully")))
                .andExpect(jsonPath("$.data", hasItem("OPERATOR")));
    }

}
