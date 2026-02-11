package com.auth.security.auth_security_app.admin.controller;

import com.auth.security.auth_security_app.admin.dto.clientDTO.ClientIdDTO;
import com.auth.security.auth_security_app.admin.dto.clientDTO.ClientRequestDTO;
import com.auth.security.auth_security_app.admin.dto.clientDTO.ClientResponseDTO;
import com.auth.security.auth_security_app.admin.service.Interface.ClientService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/admin/clients")
@RequiredArgsConstructor
//@PreAuthorize("hasRole('SAS_ADMIN')")
public class ClientController {

    private final ClientService clientService;

    @PostMapping("/createClient")
    public ResponseEntity<ClientResponseDTO> create(@RequestBody ClientRequestDTO request) {
        return ResponseEntity.ok(clientService.create(request));
    }

    @PostMapping("/getAllClients")
    public ResponseEntity<List<ClientResponseDTO>> getAll() {
        return ResponseEntity.ok(clientService.getAll());
    }

    @PostMapping("/{clientId}")
    public ResponseEntity<ClientResponseDTO> getById(@RequestBody ClientIdDTO clientId) {
        return ResponseEntity.ok(clientService.getById(clientId.getId()));
    }

    @PutMapping("/{clientId}")
    public ResponseEntity<ClientResponseDTO> update(
            @PathVariable String clientId,
            @RequestBody ClientRequestDTO request) {
        return ResponseEntity.ok(clientService.update(clientId, request));
    }

//    @DeleteMapping("/{clientId}")
//    public ResponseEntity<String> delete(@PathVariable String clientId) {
//        return ResponseEntity.ok(clientService.delete(clientId));
//    }
}
