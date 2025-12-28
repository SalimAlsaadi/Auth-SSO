package com.auth.security.auth_security_app.admin.controller;

import com.auth.security.auth_security_app.admin.dto.clientDTO.ClientRequest;
import com.auth.security.auth_security_app.admin.dto.clientDTO.ClientResponse;
import com.auth.security.auth_security_app.admin.service.Interface.ClientService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/admin/clients")
@RequiredArgsConstructor
@PreAuthorize("hasRole('SAS_ADMIN')")
public class ClientController {

    private final ClientService clientService;

    @PostMapping
    public ResponseEntity<ClientResponse> create(@RequestBody ClientRequest request) {
        return ResponseEntity.ok(clientService.create(request));
    }

    @GetMapping
    public ResponseEntity<List<ClientResponse>> getAll() {
        return ResponseEntity.ok(clientService.getAll());
    }

    @GetMapping("/{clientId}")
    public ResponseEntity<ClientResponse> getById(@PathVariable String clientId) {
        return ResponseEntity.ok(clientService.getById(clientId));
    }

    @PutMapping("/{clientId}")
    public ResponseEntity<ClientResponse> update(
            @PathVariable String clientId,
            @RequestBody ClientRequest request) {
        return ResponseEntity.ok(clientService.update(clientId, request));
    }

//    @DeleteMapping("/{clientId}")
//    public ResponseEntity<String> delete(@PathVariable String clientId) {
//        return ResponseEntity.ok(clientService.delete(clientId));
//    }
}
