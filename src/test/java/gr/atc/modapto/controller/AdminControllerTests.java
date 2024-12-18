package gr.atc.modapto.controller;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.is;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.when;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.test.context.support.WithMockUser;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.ObjectMapper;

import gr.atc.modapto.dto.UserDTO;
import gr.atc.modapto.dto.UserRoleDTO;
import gr.atc.modapto.enums.PilotCode;
import gr.atc.modapto.enums.PilotRole;
import gr.atc.modapto.service.AdminService;

@WebMvcTest(AdminController.class)
class AdminControllerTests {

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private AdminService adminService;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private static Jwt jwt;

    @BeforeAll
    @SuppressWarnings("unused")
    static void setup() {
        String tokenValue = "mock.jwt.token";
        Map<String, Object> claims = new HashMap<>();
        claims.put("realm_access", Map.of("roles", List.of("SUPER_ADMIN")));
        claims.put("resource_access", Map.of("modapto", Map.of("roles", List.of("SUPER_ADMIN"))));
        claims.put("sid", "user");
        claims.put("pilot_code", List.of("SEW"));
        claims.put("user_role",  List.of("TEST"));
        claims.put("pilot_role",  List.of("ADMIN"));

        jwt = Jwt.withTokenValue(tokenValue)
                .headers(header -> header.put("alg", "HS256"))
                .claims(claim -> claim.putAll(claims))
                .build();
    }


    @DisplayName("Get All User Roles: Success")
    @Test
    void givenValidJwt_whenGetAllUserRoles_thenReturnUserRoles() throws Exception {
        // Given
        UserRoleDTO tempRole = new UserRoleDTO();
        tempRole.setName("Test Role");

        List<UserRoleDTO> roles = List.of(tempRole);
        given(adminService.retrieveAllUserRoles(anyString(), anyString())).willReturn(roles);

        // Mock JWT authentication
        JwtAuthenticationToken jwtAuthenticationToken = new JwtAuthenticationToken(jwt, List.of(new SimpleGrantedAuthority("ROLE_SUPER_ADMIN")));
        SecurityContextHolder.getContext().setAuthentication(jwtAuthenticationToken);

        // When
        ResultActions response = mockMvc.perform(get("/api/admin/roles")
                .contentType(MediaType.APPLICATION_JSON));

        // Then
        response.andExpect(status().isOk())
                .andExpect(jsonPath("$.success", is(true)))
                .andExpect(jsonPath("$.message", is("User roles retrieved successfully")))
                .andExpect(jsonPath("$.data[0].name", is("Test Role")));
    }

    @DisplayName("Get All User Role Names: Success")
    @Test
    void givenValidJwt_whenGetAllUserRoleNames_thenReturnUserRoleNames() throws Exception {
        // Given
        UserRoleDTO tempRole = new UserRoleDTO();
        tempRole.setName("Test Role");

        List<UserRoleDTO> roles = List.of(tempRole);
        given(adminService.retrieveAllUserRoles(anyString(), anyString())).willReturn(roles);

        // Mock JWT authentication
        JwtAuthenticationToken jwtAuthenticationToken = new JwtAuthenticationToken(jwt, List.of(new SimpleGrantedAuthority("ROLE_SUPER_ADMIN")));
        SecurityContextHolder.getContext().setAuthentication(jwtAuthenticationToken);

        // When
        ResultActions response = mockMvc.perform(get("/api/admin/roles/names")
                .contentType(MediaType.APPLICATION_JSON));

        // Then
        response.andExpect(status().isOk())
                .andExpect(jsonPath("$.success", is(true)))
                .andExpect(jsonPath("$.message", is("User role names retrieved successfully")))
                .andExpect(jsonPath("$.data[0]", is("Test Role")));
    }

    @DisplayName("Get All Pilot Codes: Success")
    @Test
    void givenValidJwt_whenGetAllPilotCodes_thenReturnPilotCodes() throws Exception {
        // Given
        List<String> pilotRoles = List.of("CRF", "SEW");
        given(adminService.retrieveAllPilots(anyString())).willReturn(pilotRoles);

        // Mock JWT authentication
        JwtAuthenticationToken jwtAuthenticationToken = new JwtAuthenticationToken(jwt, List.of(new SimpleGrantedAuthority("ROLE_SUPER_ADMIN")));
        SecurityContextHolder.getContext().setAuthentication(jwtAuthenticationToken);

        // When
        ResultActions response = mockMvc.perform(get("/api/admin/pilots")
                .contentType(MediaType.APPLICATION_JSON));

        // Then
        response.andExpect(status().isOk())
                .andExpect(jsonPath("$.success", is(true)))
                .andExpect(jsonPath("$.message", is("Pilot codes retrieved successfully")))
                .andExpect(jsonPath("$.data", is(pilotRoles)));

        assertThat(response.andReturn().getResponse().getStatus()).isEqualTo(HttpStatus.OK.value());
    }

    @DisplayName("Create new Role: Success")
    @Test
    void givenValidJwtAndNewRole_whenCreateNewUserRole_thenReturnSuccess() throws Exception {
        // Given
        UserRoleDTO role = UserRoleDTO.builder()
                .name("Test Role")
                .pilotRole(PilotRole.ADMIN)
                .pilotCode(PilotCode.SEW)
                .build();

        given(adminService.createUserRole(anyString(), any(UserRoleDTO.class))).willReturn(true);

        // Mock JWT authentication
        JwtAuthenticationToken jwtAuthenticationToken = new JwtAuthenticationToken(jwt, List.of(new SimpleGrantedAuthority("ROLE_SUPER_ADMIN")));
        SecurityContextHolder.getContext().setAuthentication(jwtAuthenticationToken);

        // When
        ResultActions response = mockMvc.perform(MockMvcRequestBuilders.post("/api/admin/roles/create")
                .contentType(MediaType.APPLICATION_JSON)
                .with(csrf())
                .content(objectMapper.writeValueAsString(role)));

        // Then
        response.andExpect(status().isCreated())
                .andExpect(jsonPath("$.success", is(true)))
                .andExpect(jsonPath("$.message", is("User role created successfully")));
    }

    @DisplayName("Create new Role: Unauthorized Admin request")
    @Test
    void givenValidJwtAndNewRole_whenCreateNewUserRole_thenReturnUnauthorizedForAdminInDifferentPilots() throws Exception {
        // Given
        UserRoleDTO role = UserRoleDTO.builder()
                .name("Test Role")
                .pilotRole(PilotRole.ADMIN)
                .pilotCode(PilotCode.CRF)
                .build();

        given(adminService.createUserRole(anyString(), any(UserRoleDTO.class))).willReturn(true);

        // Mock JWT authentication
        JwtAuthenticationToken jwtAuthenticationToken = new JwtAuthenticationToken(jwt, List.of(new SimpleGrantedAuthority("ROLE_ADMIN")));
        SecurityContextHolder.getContext().setAuthentication(jwtAuthenticationToken);

        // When
        ResultActions response = mockMvc.perform(MockMvcRequestBuilders.post("/api/admin/roles/create")
                .contentType(MediaType.APPLICATION_JSON)
                .with(csrf())
                .content(objectMapper.writeValueAsString(role)));

        // Then
        response.andExpect(status().isForbidden())
                .andExpect(jsonPath("$.success", is(false)))
                .andExpect(jsonPath("$.message", is("Unauthorized action")));
    }

    @DisplayName("Create new Role: Internal Error")
    @Test
    void givenValidJwtAndNewRole_whenCreateNewUserRole_thenReturnInternalError() throws Exception {
        // Given
        UserRoleDTO role = UserRoleDTO.builder()
                .name("Test Role")
                .pilotRole(PilotRole.ADMIN)
                .pilotCode(PilotCode.SEW)
                .build();

        given(adminService.createUserRole(anyString(), any(UserRoleDTO.class))).willReturn(false);

        // Mock JWT authentication
        JwtAuthenticationToken jwtAuthenticationToken = new JwtAuthenticationToken(jwt, List.of(new SimpleGrantedAuthority("ROLE_ADMIN")));
        SecurityContextHolder.getContext().setAuthentication(jwtAuthenticationToken);

        // When
        ResultActions response = mockMvc.perform(MockMvcRequestBuilders.post("/api/admin/roles/create")
                .contentType(MediaType.APPLICATION_JSON)
                .with(csrf())
                .content(objectMapper.writeValueAsString(role)));

        // Then
        response.andExpect(status().isInternalServerError())
                .andExpect(jsonPath("$.success", is(false)))
                .andExpect(jsonPath("$.message", is("Unable to create and store the new user role")));
    }

    @DisplayName("Create new Role: Missing Fields")
    @Test
    void givenValidJwtAndNewRoleWithMissingFields_whenCreateNewUserRole_thenReturnBadRequest() throws Exception {
        // Given
        UserRoleDTO role = UserRoleDTO.builder()
                .name("Test Role")
                .pilotRole(PilotRole.ADMIN)
                .build();


        // Mock JWT authentication
        JwtAuthenticationToken jwtAuthenticationToken = new JwtAuthenticationToken(jwt, List.of(new SimpleGrantedAuthority("ROLE_ADMIN")));
        SecurityContextHolder.getContext().setAuthentication(jwtAuthenticationToken);

        // When
        ResultActions response = mockMvc.perform(MockMvcRequestBuilders.post("/api/admin/roles/create")
                .contentType(MediaType.APPLICATION_JSON)
                .with(csrf())
                .content(objectMapper.writeValueAsString(role)));

        // Then
        response.andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.success", is(false)))
                .andExpect(jsonPath("$.message", is("All fields of roles must be inserted (Name, Pilot Code, Pilot Type)")));
    }

    @DisplayName("Delete User Role: Success")
    @Test
    void givenValidJwtAndRoleName_whenDeleteUserRole_thenReturnSuccess() throws Exception {
        // Given
        String roleName = "TestRole";

        // Mock service to return true for successful deletion
        given(adminService.retrieveUserRole(anyString(), eq(roleName.toUpperCase())))
                .willReturn(UserRoleDTO.builder().pilotCode(PilotCode.SEW).build());
        given(adminService.deleteUserRole(anyString(), eq(roleName.toUpperCase()))).willReturn(true);

        // Mock JWT authentication
        JwtAuthenticationToken jwtAuthenticationToken = new JwtAuthenticationToken(jwt,
                List.of(new SimpleGrantedAuthority("ROLE_SUPER_ADMIN")));
        SecurityContextHolder.getContext().setAuthentication(jwtAuthenticationToken);

        // When
        ResultActions response = mockMvc.perform(MockMvcRequestBuilders.delete("/api/admin/roles/{roleName}", roleName)
                .with(csrf())
                .contentType(MediaType.APPLICATION_JSON));

        // Then
        response.andExpect(status().isOk())
                .andExpect(jsonPath("$.success", is(true)))
                .andExpect(jsonPath("$.message", is("User role deleted successfully")));
    }

    @DisplayName("Delete User Role: Admin Unauthorized for Different Pilot")
    @Test
    void givenValidJwt_whenDeleteUserRoleInDifferentPilot_thenReturnForbidden() throws Exception {
        // Given
        String roleName = "TestRole";

        // Mock service to return role from different pilot
        given(adminService.retrieveUserRole(anyString(), eq(roleName.toUpperCase())))
                .willReturn(UserRoleDTO.builder().pilotCode(PilotCode.CRF).build());

        // Mock JWT authentication
        JwtAuthenticationToken jwtAuthenticationToken = new JwtAuthenticationToken(jwt,
                List.of(new SimpleGrantedAuthority("ROLE_ADMIN")));
        SecurityContextHolder.getContext().setAuthentication(jwtAuthenticationToken);

        // When
        ResultActions response = mockMvc.perform(MockMvcRequestBuilders.delete("/api/admin/roles/{roleName}", roleName)
                .with(csrf())
                .contentType(MediaType.APPLICATION_JSON));

        // Then
        response.andExpect(status().isForbidden())
                .andExpect(jsonPath("$.success", is(false)))
                .andExpect(jsonPath("$.message", is("Unauthorized action")));
    }

    @DisplayName("Delete User Role: Deletion Failure")
    @Test
    void givenValidJwt_whenDeleteUserRole_thenReturnInternalServerError() throws Exception {
        // Given
        String roleName = "TestRole";

        // Mock service to return role
        given(adminService.retrieveUserRole(anyString(), eq(roleName.toUpperCase())))
                .willReturn(UserRoleDTO.builder().pilotCode(PilotCode.SEW).build());

        // Mock service to fail deletion
        given(adminService.deleteUserRole(anyString(), eq(roleName))).willReturn(false);

        // Mock JWT authentication
        JwtAuthenticationToken jwtAuthenticationToken = new JwtAuthenticationToken(jwt,
                List.of(new SimpleGrantedAuthority("ROLE_SUPER_ADMIN")));
        SecurityContextHolder.getContext().setAuthentication(jwtAuthenticationToken);

        // When
        ResultActions response = mockMvc.perform(MockMvcRequestBuilders.delete("/api/admin/roles/{roleName}", roleName)
                .with(csrf())
                .contentType(MediaType.APPLICATION_JSON));

        // Then
        response.andExpect(status().isInternalServerError())
                .andExpect(jsonPath("$.success", is(false)))
                .andExpect(jsonPath("$.message", is("Unable to delete the user role")));
    }

    @DisplayName("Retrieve User Role: Success")
    @Test
    void givenValidJwt_whenRetrieveUserRole_thenReturnUserRole() throws Exception {
        // Given
        String roleName = "TestRole";
        UserRoleDTO expectedRole = UserRoleDTO.builder()
                .name(roleName)
                .pilotCode(PilotCode.SEW)
                .pilotRole(PilotRole.ADMIN)
                .build();

        // Mock service to return role
        given(adminService.retrieveUserRole(anyString(), eq(roleName.toUpperCase()))).willReturn(expectedRole);

        // Mock JWT authentication
        JwtAuthenticationToken jwtAuthenticationToken = new JwtAuthenticationToken(jwt,
                List.of(new SimpleGrantedAuthority("ROLE_SUPER_ADMIN")));
        SecurityContextHolder.getContext().setAuthentication(jwtAuthenticationToken);

        // When
        ResultActions response = mockMvc.perform(MockMvcRequestBuilders.get("/api/admin/roles/{roleName}", roleName)
                .contentType(MediaType.APPLICATION_JSON));

        // Then
        response.andExpect(status().isOk())
                .andExpect(jsonPath("$.success", is(true)))
                .andExpect(jsonPath("$.message", is("User role retrieved successfully")))
                .andExpect(jsonPath("$.data.name", is(roleName)));
    }

    @DisplayName("Update User Role: Success")
    @Test
    void givenValidJwtAndRole_whenUpdateUserRole_thenReturnSuccess() throws Exception {
        // Given
        String roleName = "TestRole";
        UserRoleDTO roleToUpdate = UserRoleDTO.builder()
                .name(roleName.toUpperCase())
                .pilotCode(PilotCode.SEW)
                .pilotRole(PilotRole.ADMIN)
                .build();

        // Mock service to return true for successful update
        given(adminService.updateUserRole(anyString(), eq(roleToUpdate), eq(roleName.toUpperCase())))
                .willReturn(true);

        // Mock JWT authentication
        JwtAuthenticationToken jwtAuthenticationToken = new JwtAuthenticationToken(jwt,
                List.of(new SimpleGrantedAuthority("ROLE_SUPER_ADMIN")));
        SecurityContextHolder.getContext().setAuthentication(jwtAuthenticationToken);

        // When
        ResultActions response = mockMvc.perform(MockMvcRequestBuilders.put("/api/admin/roles/{roleName}", roleName)
                .with(csrf())
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(roleToUpdate)));

        // Then
        response.andExpect(status().isOk())
                .andExpect(jsonPath("$.success", is(true)))
                .andExpect(jsonPath("$.message", is("User role updated successfully")));
    }

    @DisplayName("Update User Role: Admin Unauthorized for Different Pilot")
    @Test
    void givenValidJwt_whenUpdateUserRoleInDifferentPilot_thenReturnForbidden() throws Exception {
        // Given
        String roleName = "TestRole";
        UserRoleDTO roleToUpdate = UserRoleDTO.builder()
                .name(roleName)
                .pilotCode(PilotCode.CRF)
                .pilotRole(PilotRole.ADMIN)
                .build();


        // Mock JWT authentication
        JwtAuthenticationToken jwtAuthenticationToken = new JwtAuthenticationToken(jwt,
                List.of(new SimpleGrantedAuthority("ROLE_ADMIN")));
        SecurityContextHolder.getContext().setAuthentication(jwtAuthenticationToken);

        // When
        ResultActions response = mockMvc.perform(MockMvcRequestBuilders.put("/api/admin/roles/{roleName}", roleName)
                .with(csrf())
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(roleToUpdate)));

        // Then
        response.andExpect(status().isForbidden())
                .andExpect(jsonPath("$.success", is(false)))
                .andExpect(jsonPath("$.message", is("Unauthorized action")));
    }

    @DisplayName("Update User Role: Super-Admin role unauthorized update")
    @Test
    void givenValidJwtAndNoSuperAdminUser_whenUpdateUserRoleInSuperAdmin_thenReturnForbidden() throws Exception {
        // Given
        String roleName = "TestRole";
        UserRoleDTO roleToUpdate = UserRoleDTO.builder()
                .name(roleName)
                .pilotRole(PilotRole.SUPER_ADMIN)
                .build();


        // Mock JWT authentication
        JwtAuthenticationToken jwtAuthenticationToken = new JwtAuthenticationToken(jwt,
                List.of(new SimpleGrantedAuthority("ROLE_ADMIN")));
        SecurityContextHolder.getContext().setAuthentication(jwtAuthenticationToken);

        // When
        ResultActions response = mockMvc.perform(MockMvcRequestBuilders.put("/api/admin/roles/{roleName}", roleName)
                .with(csrf())
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(roleToUpdate)));

        // Then
        response.andExpect(status().isForbidden())
                .andExpect(jsonPath("$.success", is(false)))
                .andExpect(jsonPath("$.message", is("Unauthorized action")));
    }

    @DisplayName("Update User Role: Update Failure")
    @Test
    void givenValidJwt_whenUpdateUserRole_thenReturnInternalServerError() throws Exception {
        // Given
        String roleName = "TestRole";
        UserRoleDTO roleToUpdate = UserRoleDTO.builder()
                .name(roleName)
                .pilotCode(PilotCode.SEW)
                .pilotRole(PilotRole.ADMIN)
                .build();

        // Mock service to return false for update
        given(adminService.updateUserRole(anyString(), eq(roleToUpdate), eq(roleName)))
                .willReturn(false);

        // Mock JWT authentication
        JwtAuthenticationToken jwtAuthenticationToken = new JwtAuthenticationToken(jwt,
                List.of(new SimpleGrantedAuthority("ROLE_SUPER_ADMIN")));
        SecurityContextHolder.getContext().setAuthentication(jwtAuthenticationToken);

        // When
        ResultActions response = mockMvc.perform(MockMvcRequestBuilders.put("/api/admin/roles/{roleName}", roleName)
                .with(csrf())
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(roleToUpdate)));

        // Then
        response.andExpect(status().isInternalServerError())
                .andExpect(jsonPath("$.success", is(false)))
                .andExpect(jsonPath("$.message", is("Unable to update the user role")));
    }

    @DisplayName("Get All Pilot Roles: Success")
    @Test
    void givenValidJwt_whenGetAllPilotRoles_thenReturnPilotRoles() throws Exception {
        // Given
        List<String> pilotRoles = List.of("ADMIN", "USER");
        given(adminService.retrieveAllPilotRoles(anyString(), anyBoolean())).willReturn(pilotRoles);

        // Mock JWT authentication
        JwtAuthenticationToken jwtAuthenticationToken = new JwtAuthenticationToken(jwt, List.of(new SimpleGrantedAuthority("ROLE_SUPER_ADMIN")));
        SecurityContextHolder.getContext().setAuthentication(jwtAuthenticationToken);

        // When
        ResultActions response = mockMvc.perform(get("/api/admin/pilot-roles")
                .contentType(MediaType.APPLICATION_JSON));

        // Then
        response.andExpect(status().isOk())
                .andExpect(jsonPath("$.success", is(true)))
                .andExpect(jsonPath("$.message", is("Pilot roles retrieved successfully")))
                .andExpect(jsonPath("$.data", is(pilotRoles)));

        assertThat(response.andReturn().getResponse().getStatus()).isEqualTo(HttpStatus.OK.value());
    }

    @DisplayName("Unauthorized Access: 401 Error")
    @Test
    void givenNoAuthentication_whenGetAllUserRoles_thenReturnUnauthorized() throws Exception {
        // When
        ResultActions response = mockMvc.perform(get("/api/admin/roles")
                .contentType(MediaType.APPLICATION_JSON));

        // Then
        response.andExpect(status().isUnauthorized());

        assertThat(response.andReturn().getResponse().getStatus()).isEqualTo(HttpStatus.UNAUTHORIZED.value());
    }

    @DisplayName("Forbidden Access: 403 Error")
    @WithMockUser(authorities = "ROLE_USER")
    @Test
    void givenUserWithoutSuperAdminRole_whenGetAllUserRoles_thenReturnForbidden() throws Exception {
        // When
        ResultActions response = mockMvc.perform(get("/api/admin/roles")
                .contentType(MediaType.APPLICATION_JSON));

        // Then
        response.andExpect(status().isForbidden());

        assertThat(response.andReturn().getResponse().getStatus()).isEqualTo(HttpStatus.FORBIDDEN.value());
    }

    @DisplayName("Successful retrieval of user roles for SUPER_ADMIN")
    @Test
    void givenValidJwtAndPilotCode_whenSuperAdmin_thenReturnUserRoles() throws Exception {
        // Given
        String pilotCode = "SEW";
        List<String> mockRoles = Arrays.asList("ROLE1", "ROLE2");

        // Mock JWT authentication
        JwtAuthenticationToken jwtAuthenticationToken = new JwtAuthenticationToken(jwt, List.of(new SimpleGrantedAuthority("ROLE_SUPER_ADMIN")));
        SecurityContextHolder.getContext().setAuthentication(jwtAuthenticationToken);

        // Mock service method
        when(adminService.retrieveAllUserRolesByPilot(anyString(), anyString()))
                .thenReturn(mockRoles);

        // When
        ResultActions response = mockMvc.perform(get("/api/admin/roles/pilot/{pilotCode}", pilotCode)
                .contentType(MediaType.APPLICATION_JSON));

        // Then
        response.andExpect(status().isOk())
                .andExpect(jsonPath("$.success", is(true)))
                .andExpect(jsonPath("$.message", is("User roles retrieved successfully")))
                .andExpect(jsonPath("$.data[0]", is("ROLE1")))
                .andExpect(jsonPath("$.data[1]", is("ROLE2")));
    }

    @DisplayName("Get a User Role: Forbidden for 'USER' role")
    @Test
    void givenValidJwtAndPilotCodeAndUser_whenGetUserRole_thenReturnForbidden() throws Exception {
        // Given
        String pilotCode = "SEW";

        // Mock JWT
        Jwt mockToken = createMockJwtToken("OPERATOR", "USER", "SEW");

        // Mock JWT authentication
        JwtAuthenticationToken jwtAuthenticationToken = new JwtAuthenticationToken(mockToken, List.of(new SimpleGrantedAuthority("ROLE_USER")));
        SecurityContextHolder.getContext().setAuthentication(jwtAuthenticationToken);

        // When
        ResultActions response = mockMvc.perform(MockMvcRequestBuilders.get("/api/admin/roles/pilot/{pilotCode}", pilotCode));

        // Then
        response.andExpect(status().isForbidden())
                .andExpect(jsonPath("$.success", is(false)))
                .andExpect(jsonPath("$.message", is("Unauthorized action")))
                .andExpect(jsonPath("$.errors", is("User of role 'USER' can not retrieve information for user roles")));
    }

    @DisplayName("Get a User Role: Forbidden for 'ADMIN' role")
    @Test
    void givenValidJwtAndPilotCodeAndAdminUser_whenGetARoleFromDifferentPilot_thenReturnForbidden() throws Exception {
        // Given
        String pilotCode = "CRF";

        // Mock JWT
        Jwt mockToken = createMockJwtToken("OPERATOR", "ADMIN", "SEW");

        // Mock JWT authentication
        JwtAuthenticationToken jwtAuthenticationToken = new JwtAuthenticationToken(mockToken, List.of(new SimpleGrantedAuthority("ROLE_ADMIN")));
        SecurityContextHolder.getContext().setAuthentication(jwtAuthenticationToken);

        // When
        ResultActions response = mockMvc.perform(MockMvcRequestBuilders.get("/api/admin/roles/pilot/{pilotCode}", pilotCode));

        // Then
        response.andExpect(status().isForbidden())
                .andExpect(jsonPath("$.success", is(false)))
                .andExpect(jsonPath("$.message", is("Unauthorized action")))
                .andExpect(jsonPath("$.errors", is("User of role 'ADMIN' can only retrieve user roles only inside their organization")));
    }


    @DisplayName("Successful retrieval of users for specific role")
    @Test
    void givenValidJwtAndUserRole_whenSuperAdmin_thenReturnUsers() throws Exception {
        // Given
        String userRole = "OPERATOR";
        List<UserDTO> mockUsers = Arrays.asList(
                UserDTO.builder().username("user1").build(),
                UserDTO.builder().username("user2").build()
        );

        // Mock JWT authentication
        JwtAuthenticationToken jwtAuthenticationToken = new JwtAuthenticationToken(jwt, List.of(new SimpleGrantedAuthority("ROLE_SUPER_ADMIN")));
        SecurityContextHolder.getContext().setAuthentication(jwtAuthenticationToken);

        // Mock service method
        when(adminService.retrieveAllUsersByUserRole(anyString(), anyString()))
                .thenReturn(mockUsers);

        // When
        ResultActions response = mockMvc.perform(MockMvcRequestBuilders.get("/api/admin/roles/{userRole}/users", userRole)
                .contentType(MediaType.APPLICATION_JSON));

        // Then
        response.andExpect(status().isOk())
                .andExpect(jsonPath("$.success", is(true)))
                .andExpect(jsonPath("$.message", is("Users associated with the role retrieved successfully")))
                .andExpect(jsonPath("$.data[0].username", is("user1")))
                .andExpect(jsonPath("$.data[1].username", is("user2")));
    }

    private Jwt createMockJwtToken(String userRole, String pilotRole, String pilotCode){
        String tokenValue = "mock.jwt.token";
        Map<String, Object> claims = new HashMap<>();
        claims.put("realm_access", Map.of("roles", List.of("SUPER_ADMIN")));
        claims.put("resource_access", Map.of("modapto", Map.of("roles", List.of("SUPER_ADMIN"))));
        claims.put("sub", "user");
        claims.put("pilot_code", pilotCode);
        claims.put("pilot_role", pilotRole);
        claims.put("user_role", userRole);

        return Jwt.withTokenValue(tokenValue)
                .headers(header -> header.put("alg", "HS256"))
                .claims(claim -> claim.putAll(claims))
                .build();
    }
}
