package gr.atc.modapto.service;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.client.RestTemplate;

import gr.atc.modapto.dto.UserDTO;
import gr.atc.modapto.dto.UserRoleDTO;
import gr.atc.modapto.dto.keycloak.ClientDTO;
import gr.atc.modapto.dto.keycloak.GroupDTO;
import gr.atc.modapto.dto.keycloak.RealmRoleDTO;
import gr.atc.modapto.dto.keycloak.RoleRepresentationDTO;
import gr.atc.modapto.dto.keycloak.UserRepresentationDTO;
import gr.atc.modapto.exception.CustomExceptions;

@ExtendWith(MockitoExtension.class)
class AdminServiceTests {

  @Mock
  private RestTemplate restTemplate;

  @InjectMocks
  private AdminService adminService;

  @Mock
  private KeycloakSupportService keycloakSupportService;

  private static final String MOCK_TOKEN = "mock-token";
  private static final String MOCK_ADMIN_URI = "http://mock-admin-uri";

  @BeforeEach
  void setup() {
    ReflectionTestUtils.setField(adminService, "adminUri", MOCK_ADMIN_URI);
    ReflectionTestUtils.setField(adminService, "restTemplate", restTemplate);
    ReflectionTestUtils.setField(adminService, "clientPath", "/clients");
    ReflectionTestUtils.setField(adminService, "rolePath", "/roles");
    ReflectionTestUtils.setField(adminService, "groupPath", "/groups");
  }

  @DisplayName("Retrieve all pilot roles: Success")
  @Test
  void givenValidJwt_whenGetAllPilotRoles_thenReturnPilotRoles() {
    List<RealmRoleDTO> mockRoles =
        Arrays.asList(new RealmRoleDTO("1", "ADMIN", null, false, false, null),
            new RealmRoleDTO("2", "USER", null, false, false, null),
            new RealmRoleDTO("3", "default-roles-modapto-system", null, false, false, null));

    ResponseEntity<List<RealmRoleDTO>> mockResponse =
        new ResponseEntity<>(mockRoles, HttpStatus.OK);

    when(restTemplate.exchange(anyString(), eq(HttpMethod.GET), any(),
        any(ParameterizedTypeReference.class))).thenReturn(mockResponse);

    List<String> result = adminService.retrieveAllPilotRoles(MOCK_TOKEN, true);

    assertEquals(2, result.size());
    assertTrue(result.contains("ADMIN"));
    assertTrue(result.contains("USER"));
    assertFalse(result.contains("default-roles-modapto-system"));
  }

  @DisplayName("Retrieve all pilot roles: Empty Response - Fail")
  @Test
  void givenEmptyResponse_whenGetAllPilotRoles_thenReturnEmptyList() {
    ResponseEntity<List<RealmRoleDTO>> mockResponse =
        new ResponseEntity<>(Collections.emptyList(), HttpStatus.OK);

    when(restTemplate.exchange(anyString(), eq(HttpMethod.GET), any(),
        any(ParameterizedTypeReference.class))).thenReturn(mockResponse);

    List<String> result = adminService.retrieveAllPilotRoles(MOCK_TOKEN, true);

    assertTrue(result.isEmpty());
  }

  @DisplayName("Retrieve all user roles: Invalid Response - Fail")
  @Test
  void givenInvalidResponse_whenGetAllUserRoles_thenReturnEmptyList() {
    // Given
    when(keycloakSupportService.getClientId()).thenReturn("client-id");

    // When
    when(restTemplate.exchange(anyString(), eq(HttpMethod.GET), any(),
        any(ParameterizedTypeReference.class)))
            .thenThrow(new HttpClientErrorException(HttpStatus.BAD_REQUEST));


    // Then
    assertThrows(CustomExceptions.KeycloakException.class,
        () -> adminService.retrieveAllUserRoles(MOCK_TOKEN, null));
  }

  @DisplayName("Retrieve all pilots: Success")
  @Test
  void givenValidJwt_whenGetAllPilots_thenReturnPilots() {
    List<GroupDTO> mockGroups = Arrays.asList(new GroupDTO("1", "SEW", null, 0, null),
        new GroupDTO("2", "CRF", null, 0, null));

    ResponseEntity<List<GroupDTO>> mockResponse = new ResponseEntity<>(mockGroups, HttpStatus.OK);

    when(restTemplate.exchange(anyString(), eq(HttpMethod.GET), any(),
        any(ParameterizedTypeReference.class))).thenReturn(mockResponse);

    List<String> result = adminService.retrieveAllPilots(MOCK_TOKEN);

    assertEquals(2, result.size());
    assertTrue(result.contains("SEW"));
    assertTrue(result.contains("CRF"));
  }

  @DisplayName("Retrieve all user roles: Success")
  @Test
  void givenValidJwt_whenGetAllUserRoles_thenReturnUserRoles() {
    Map<String, List<String>> attributes = new HashMap<>();
    attributes.put("pilot_code", List.of("CRF"));

    List<RoleRepresentationDTO> mockRoles = Arrays.asList(
        RoleRepresentationDTO.builder().id("1").name("OPERATOR").composite(false).clientRole(true)
            .attributes(attributes).build(),
        RoleRepresentationDTO.builder().id("2").name("LOGISTICS_MANAGER").composite(false)
            .clientRole(true).attributes(attributes).build());

    when(keycloakSupportService.getClientId()).thenReturn("client-id");

    // Mock REST template response
    lenient().when(restTemplate.exchange(
        eq(MOCK_ADMIN_URI + "/clients/client-id/roles?briefRepresentation=false"),
        eq(HttpMethod.GET), any(HttpEntity.class), any(ParameterizedTypeReference.class)))
            .thenReturn(new ResponseEntity<>(mockRoles, HttpStatus.OK));

    // When
    List<UserRoleDTO> result = adminService.retrieveAllUserRoles(MOCK_TOKEN, "ALL");

    // Then
    assertNotNull(result);
    assertEquals(2, result.size());
  }

  @DisplayName("Retrieve all user roles: Client Not Found - Fail")
  @Test
  void givenClientNotFound_whenGetAllUserRoles_thenReturnEmptyList() {
    ResponseEntity<List<ClientDTO>> mockClientResponse =
        new ResponseEntity<>(Collections.emptyList(), HttpStatus.OK);

    when(keycloakSupportService.getClientId()).thenReturn(null);

    lenient().when(restTemplate.exchange(eq(MOCK_ADMIN_URI + "/clients"), eq(HttpMethod.GET), any(),
        any(ParameterizedTypeReference.class))).thenReturn(mockClientResponse);

    List<UserRoleDTO> result = adminService.retrieveAllUserRoles(MOCK_TOKEN, null);

    assertTrue(result.isEmpty());
  }

  @DisplayName("Delete User Role: Success")
  @Test
  void givenValidJwtAndRoleName_whenDeleteUserRole_thenReturnSuccess() {
    // Given
    String mockToken = "mock-jwt-token";
    String roleName = "TEST_ROLE";
    String mockClientId = "test-client-id";

    // Mock dependencies
    when(keycloakSupportService.getClientId()).thenReturn(mockClientId);

    String expectedUri = MOCK_ADMIN_URI + "/clients/" + mockClientId + "/roles/" + roleName;

    // When
    ResponseEntity<Void> mockResponse = ResponseEntity.ok().build();
    when(restTemplate.exchange(eq(expectedUri), eq(HttpMethod.DELETE), any(HttpEntity.class),
        eq(Void.class))).thenReturn(mockResponse);

    // Then
    boolean result = adminService.deleteUserRole(mockToken, roleName);

    assertTrue(result);
    verify(keycloakSupportService).getClientId();
    verify(restTemplate).exchange(eq(expectedUri), eq(HttpMethod.DELETE), any(HttpEntity.class),
        eq(Void.class));
  }

  @DisplayName("Delete User Role: Failure due to HTTP Client Error")
  @Test
  void givenValidJwtAndRoleName_whenDeleteUserRole_thenThrowKeycloakException() {
    // Given
    String mockToken = "mock-jwt-token";
    String roleName = "TEST_ROLE";
    String mockClientId = "test-client-id";

    // Mock dependencies
    when(keycloakSupportService.getClientId()).thenReturn(mockClientId);

    String expectedUri = MOCK_ADMIN_URI + "/clients/" + mockClientId + "/roles/" + roleName;

    // When
    when(restTemplate.exchange(eq(expectedUri), eq(HttpMethod.DELETE), any(HttpEntity.class),
        eq(Void.class))).thenThrow(new HttpServerErrorException(HttpStatus.BAD_REQUEST));

    // Then
    assertThrows(CustomExceptions.KeycloakException.class, () -> {
      adminService.deleteUserRole(mockToken, roleName);
    });

    verify(keycloakSupportService).getClientId();
    verify(restTemplate).exchange(eq(expectedUri), eq(HttpMethod.DELETE), any(HttpEntity.class),
        eq(Void.class));
  }

  @DisplayName("Delete User Role: Failure due to Client ID Not Found")
  @Test
  void givenValidJwtAndRoleName_whenDeleteUserRole_thenThrowDataRetrievalException() {
    // Given
    String mockToken = "mock-jwt-token";
    String roleName = "TEST_ROLE";

    // Mock dependencies
    when(keycloakSupportService.getClientId()).thenReturn(null);

    // When - Throw Exception
    assertThrows(CustomExceptions.DataRetrievalException.class, () -> {
      adminService.deleteUserRole(mockToken, roleName);
    });

    // Then
    verify(keycloakSupportService).getClientId();
    verifyNoInteractions(restTemplate);
  }


  @DisplayName("Update User Role: Failure due to Client ID Not Found")
  @Test
  void givenValidJwtAndUserRole_whenUpdateUserRole_thenThrowDataRetrievalException() {
    // Given
    String mockToken = "mock-jwt-token";
    UserRoleDTO userRole = new UserRoleDTO();
    String existingRoleName = "EXISTING_ROLE";

    // Mock dependencies
    when(keycloakSupportService.getClientId()).thenReturn(null);

    // When
    assertThrows(CustomExceptions.DataRetrievalException.class, () -> {
      adminService.updateUserRole(mockToken, userRole, existingRoleName);
    });

    // Then
    verify(keycloakSupportService).getClientId();
    verifyNoInteractions(restTemplate);
  }

  @DisplayName("Retrieve User Role: Success")
  @Test
  void givenValidJwtAndRoleName_whenRetrieveUserRole_thenReturnSuccess() {
    // Given
    String mockToken = "mock-jwt-token";
    String roleName = "TEST_ROLE";
    String mockClientId = "test-client-id";

    // Create expected role representation
    RoleRepresentationDTO mockRoleRepr = RoleRepresentationDTO.builder().name(roleName)
        .attributes(Map.of("pilot_code", List.of("SEW"), "pilot_role", List.of("ADMIN"))).build();

    // Mock keycloakSupportService behavior
    when(keycloakSupportService.getClientId()).thenReturn(mockClientId);
    when(keycloakSupportService.findRoleRepresentationByNameAndClient(roleName, mockClientId, mockToken))
        .thenReturn(mockRoleRepr);

    // When
    UserRoleDTO resultRole = adminService.retrieveUserRole(mockToken, roleName);

    // Then
    assertNotNull(resultRole, "Retrieved role should not be null");
    assertEquals(roleName, resultRole.getName(), "Role name should match");

    // Verify service calls
    verify(keycloakSupportService, times(1)).getClientId();
    verify(keycloakSupportService, times(1)).findRoleRepresentationByNameAndClient(roleName, mockClientId,
        mockToken);
  }

  @DisplayName("Update User Role: Success")
  @Test
  void givenValidJwtAndNewRoleAttributes_whenUpdateUserRole_thenReturnSuccess() {
    // Given
    String mockToken = "mock-jwt-token";
    String roleName = "TEST_ROLE";
    String mockClientId = "test-client-id";
    String updateRoleRequestUri = MOCK_ADMIN_URI + "/clients/" + mockClientId + "/roles/TEST_ROLE";
    UserRoleDTO updatedRole = UserRoleDTO.builder().name("NEW_TEST_ROLE").build();

    RoleRepresentationDTO tempRoleRepr = RoleRepresentationDTO.builder().name("TEST_ROLE")
        .attributes(Map.of("pilot_code", List.of("SEW"), "pilot_role", List.of("ADMIN"))).build();

    // Mock keycloakSupportService behavior
    when(keycloakSupportService.getClientId()).thenReturn(mockClientId);
    when(keycloakSupportService.findRoleRepresentationByNameAndClient(roleName, mockClientId, mockToken))
        .thenReturn(tempRoleRepr);

    // Mock restTemplate behavior
    when(restTemplate.exchange(eq(updateRoleRequestUri), eq(HttpMethod.PUT), any(HttpEntity.class),
        eq(Void.class))).thenReturn(new ResponseEntity<>(HttpStatus.NO_CONTENT));

    // When
    boolean response = adminService.updateUserRole(mockToken, updatedRole, roleName);

    // Then
    assertTrue(response);
    verify(keycloakSupportService, times(1)).getClientId();
    verify(keycloakSupportService, times(1)).findRoleRepresentationByNameAndClient(roleName, mockClientId,
        mockToken);
    verify(restTemplate, times(1)).exchange(eq(updateRoleRequestUri), eq(HttpMethod.PUT),
        any(HttpEntity.class), eq(Void.class));
  }

  @DisplayName("Retrieve All User Roles By Pilot: Success")
  @Test
  void givenValidJwtAndPilotCode_whenRetrieveAllUserRolesByPilot_thenReturnSuccess() {
    // Given
    String mockToken = "mock-jwt-token";
    String pilotCode = "SEW";
    String mockClientId = "test-client-id";
    String mockGroupId = "test-group-id";

    // Mock dependencies
    when(keycloakSupportService.getClientId()).thenReturn(mockClientId);
    when(keycloakSupportService.retrievePilotCodeID(pilotCode, mockToken)).thenReturn(mockGroupId);

    // Prepare test data
    List<RoleRepresentationDTO> mockRoles =
        Arrays.asList(RoleRepresentationDTO.builder().name("OPERATOR").build(),
            RoleRepresentationDTO.builder().name("MANAGER").build());

    String expectedUri =
        MOCK_ADMIN_URI + "/groups/" + mockGroupId + "/role-mappings/clients/" + mockClientId;

    // Mock the response
    ResponseEntity<List<RoleRepresentationDTO>> mockResponse =
        new ResponseEntity<>(mockRoles, HttpStatus.OK);
    when(restTemplate.exchange(eq(expectedUri), eq(HttpMethod.GET), any(HttpEntity.class),
        any(ParameterizedTypeReference.class))).thenReturn(mockResponse);

    // When
    List<String> retrievedRoles = adminService.retrieveAllUserRolesByPilot(mockToken, pilotCode);

    // Then
    assertNotNull(retrievedRoles);
    assertEquals(2, retrievedRoles.size());
  }

  @DisplayName("Retrieve All User Roles By Pilot: Failure due to Client ID Not Found")
  @Test
  void givenValidJwtAndPilotCode_whenRetrieveAllUserRolesByPilot_thenThrowDataRetrievalException() {
    // Given
    String mockToken = "mock-jwt-token";
    String pilotCode = "SEW";

    // Mock dependencies
    when(keycloakSupportService.getClientId()).thenReturn(null);

    // When & Then
    assertThrows(CustomExceptions.DataRetrievalException.class, () -> {
      adminService.retrieveAllUserRolesByPilot(mockToken, pilotCode);
    });

    // Verify interactions
    verify(keycloakSupportService).getClientId();
    verifyNoInteractions(restTemplate);
  }

  @DisplayName("Retrieve All Users By User Role: Success")
  @Test
  void givenValidJwtAndUserRole_whenRetrieveAllUsersByUserRole_thenReturnSuccess() {
    // Given
    String mockToken = "mock-jwt-token";
    String userRole = "ADMIN_ROLE";
    String mockClientId = "test-client-id";

    // Mock dependencies
    when(keycloakSupportService.getClientId()).thenReturn(mockClientId);

    // Prepare test data
    List<UserRepresentationDTO> mockUsers = Arrays.asList(
        UserRepresentationDTO.builder().username("user1").email("user1@example.com").build(),
        UserRepresentationDTO.builder().username("user2").email("user2@example.com").build());

    String expectedUri =
        MOCK_ADMIN_URI + "/clients/" + mockClientId + "/roles/" + userRole + "/users";

    // Mock the response
    ResponseEntity<List<UserRepresentationDTO>> mockResponse =
        new ResponseEntity<>(mockUsers, HttpStatus.OK);
    when(restTemplate.exchange(eq(expectedUri), eq(HttpMethod.GET), any(HttpEntity.class),
        any(ParameterizedTypeReference.class))).thenReturn(mockResponse);

    // When
    List<UserDTO> retrievedUsers = adminService.retrieveAllUsersByUserRole(mockToken, userRole);

    // Then
    assertNotNull(retrievedUsers);
    assertEquals(2, retrievedUsers.size());
    assertEquals("user1", retrievedUsers.get(0).getUsername());
    assertEquals("user2", retrievedUsers.get(1).getUsername());

    // Verify interactions
    verify(keycloakSupportService).getClientId();
    verify(restTemplate).exchange(eq(expectedUri), eq(HttpMethod.GET), any(HttpEntity.class),
        any(ParameterizedTypeReference.class));
  }

  @DisplayName("Retrieve All Users By User Role: Failure due to Client ID Not Found")
  @Test
  void givenValidJwtAndUserRole_whenRetrieveAllUsersByUserRole_thenThrowDataRetrievalException() {
    // Given
    String mockToken = "mock-jwt-token";
    String userRole = "ADMIN_ROLE";

    // Mock dependencies
    when(keycloakSupportService.getClientId()).thenReturn(null);

    // When & Then
    assertThrows(CustomExceptions.DataRetrievalException.class, () -> {
      adminService.retrieveAllUsersByUserRole(mockToken, userRole);
    });

    // Verify interactions
    verify(keycloakSupportService).getClientId();
    verifyNoInteractions(restTemplate);
  }


}
