package com.auth.security.auth_security_app.admin.service.Interface;

import com.auth.security.auth_security_app.admin.dto.clientDTO.ClientRequest;
import com.auth.security.auth_security_app.admin.dto.clientDTO.ClientResponse;

import java.util.List;

public interface ClientService {

    ClientResponse create(ClientRequest req);

    List<ClientResponse> getAll();

    ClientResponse getById(String clientId);

    ClientResponse update(String clientId, ClientRequest req);

}
