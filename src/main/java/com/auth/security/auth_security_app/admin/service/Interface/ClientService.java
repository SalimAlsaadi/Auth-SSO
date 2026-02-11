package com.auth.security.auth_security_app.admin.service.Interface;

import com.auth.security.auth_security_app.admin.dto.clientDTO.ClientRequestDTO;
import com.auth.security.auth_security_app.admin.dto.clientDTO.ClientResponseDTO;

import java.util.List;

public interface ClientService {

    ClientResponseDTO create(ClientRequestDTO req);

    List<ClientResponseDTO> getAll();

    ClientResponseDTO getById(Integer id);

    ClientResponseDTO update(String clientId, ClientRequestDTO req);

}
