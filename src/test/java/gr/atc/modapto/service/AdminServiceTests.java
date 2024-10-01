package gr.atc.modapto.service;

import gr.atc.modapto.dto.keycloak.ClientDTO;
import gr.atc.modapto.dto.keycloak.ClientRoleDTO;
import gr.atc.modapto.dto.keycloak.GroupDTO;
import gr.atc.modapto.dto.keycloak.RealmRoleDTO;
import gr.atc.modapto.exception.CustomExceptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AdminServiceTests {

    @Mock
    private RestTemplate restTemplate;

    @InjectMocks
    private AdminService adminService;

    private static final String MOCK_TOKEN = "mock-token";
    private static final String MOCK_ADMIN_URI = "http://mock-admin-uri";
    private static final String MOCK_CLIENT_NAME = "mock-client";

    @BeforeEach
    void setup() {
        ReflectionTestUtils.setField(adminService, "adminUri", MOCK_ADMIN_URI);
        ReflectionTestUtils.setField(adminService, "clientName", MOCK_CLIENT_NAME);
        ReflectionTestUtils.setField(adminService, "restTemplate", restTemplate);
    }

    @DisplayName("Retrieve all user roles: Success")
    @Test
    void givenValidJwt_whenGetAllUserRoles_thenReturnUserRoles() {
        List<RealmRoleDTO> mockRoles = Arrays.asList(
                new RealmRoleDTO("1", "ADMIN", null, false, false, null),
                new RealmRoleDTO("2", "USER", null, false, false, null),
                new RealmRoleDTO("3", "default-roles-modapto-dev", null, false, false, null)
        );

        ResponseEntity<List<RealmRoleDTO>> mockResponse = new ResponseEntity<>(mockRoles, HttpStatus.OK);

        when(restTemplate.exchange(
                anyString(),
                eq(HttpMethod.GET),
                any(),
                any(ParameterizedTypeReference.class)
        )).thenReturn(mockResponse);

        List<String> result = adminService.retrieveAllUserRoles(MOCK_TOKEN);

        assertEquals(2, result.size());
        assertTrue(result.contains("ADMIN"));
        assertTrue(result.contains("USER"));
        assertFalse(result.contains("default-roles-modapto-dev"));
    }

    @DisplayName("Retrieve all user roles: Empty Response - Fail")
    @Test
    void givenEmptyResponse_whenGetAllUserRoles_thenReturnEmptyList() {
        ResponseEntity<List<RealmRoleDTO>> mockResponse = new ResponseEntity<>(Collections.emptyList(), HttpStatus.OK);

        when(restTemplate.exchange(
                anyString(),
                eq(HttpMethod.GET),
                any(),
                any(ParameterizedTypeReference.class)
        )).thenReturn(mockResponse);

        List<String> result = adminService.retrieveAllUserRoles(MOCK_TOKEN);

        assertTrue(result.isEmpty());
    }

    @DisplayName("Retrieve all user roles: Invalid Response - Fail")
    @Test
    void givenInvalidResponse_whenGetAllUserRoles_thenReturnEmptyList() {
        when(restTemplate.exchange(
                anyString(),
                eq(HttpMethod.GET),
                any(),
                any(ParameterizedTypeReference.class)
        )).thenThrow(new HttpClientErrorException(HttpStatus.BAD_REQUEST));


        // When - Then
        assertThrows(CustomExceptions.KeycloakException.class, () -> adminService.retrieveAllUserRoles(MOCK_TOKEN));
    }

    @DisplayName("Retrieve all pilots: Success")
    @Test
    void givenValidJwt_whenGetAllPilots_thenReturnPilots() {
        List<GroupDTO> mockGroups = Arrays.asList(
                new GroupDTO("1", "SEW", null, 0, null),
                new GroupDTO("2", "CRF", null, 0, null)
        );

        ResponseEntity<List<GroupDTO>> mockResponse = new ResponseEntity<>(mockGroups, HttpStatus.OK);

        when(restTemplate.exchange(
                anyString(),
                eq(HttpMethod.GET),
                any(),
                any(ParameterizedTypeReference.class)
        )).thenReturn(mockResponse);

        List<String> result = adminService.retrieveAllPilots(MOCK_TOKEN);

        assertEquals(2, result.size());
        assertTrue(result.contains("SEW"));
        assertTrue(result.contains("CRF"));
    }

    @DisplayName("Retrieve all pilot roles: Success")
    @Test
    void givenValidJwt_whenGetAllPilotRoles_thenReturnPilotRoles() {
        List<ClientDTO> mockClients = Collections.singletonList(
                new ClientDTO("client-id", MOCK_CLIENT_NAME, null, true, null)
        );

        List<ClientRoleDTO> mockRoles = Arrays.asList(
                new ClientRoleDTO("1", "OPERATOR", null, false, false),
                new ClientRoleDTO("2", "LOGISTICS_MANAGER", null, false, false)
        );

        ResponseEntity<List<ClientDTO>> mockClientResponse = new ResponseEntity<>(mockClients, HttpStatus.OK);
        ResponseEntity<List<ClientRoleDTO>> mockRoleResponse = new ResponseEntity<>(mockRoles, HttpStatus.OK);

        when(restTemplate.exchange(
                eq(MOCK_ADMIN_URI + "/clients"),
                eq(HttpMethod.GET),
                any(),
                any(ParameterizedTypeReference.class)
        )).thenReturn(mockClientResponse);

        when(restTemplate.exchange(
                eq(MOCK_ADMIN_URI + "/clients/client-id/roles"),
                eq(HttpMethod.GET),
                any(),
                any(ParameterizedTypeReference.class)
        )).thenReturn(mockRoleResponse);

        List<String> result = adminService.retrieveAllPilotRoles(MOCK_TOKEN);

        assertEquals(2, result.size());
        assertTrue(result.contains("OPERATOR"));
        assertTrue(result.contains("LOGISTICS_MANAGER"));
    }

    @DisplayName("Retrieve all pilot roles: Client Not Found - Fail")
    @Test
    void givenClientNotFound_whenGetAllPilotRoles_thenReturnEmptyList() {
        ResponseEntity<List<ClientDTO>> mockClientResponse = new ResponseEntity<>(Collections.emptyList(), HttpStatus.OK);

        when(restTemplate.exchange(
                eq(MOCK_ADMIN_URI + "/clients"),
                eq(HttpMethod.GET),
                any(),
                any(ParameterizedTypeReference.class)
        )).thenReturn(mockClientResponse);

        List<String> result = adminService.retrieveAllPilotRoles(MOCK_TOKEN);

        assertTrue(result.isEmpty());
    }

}
