package gr.atc.modapto.service;

import java.util.List;

public interface IAdminService {

    List<String> retrieveAllUserRoles(String token);

    List<String> retrieveAllPilots(String token);

    List<String> retrieveAllPilotRoles(String token);
}

