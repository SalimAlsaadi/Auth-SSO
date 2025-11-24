package com.auth.security.auth_security_app.admin.controller;

import com.auth.security.auth_security_app.admin.dto.RoleRequest;
import com.auth.security.auth_security_app.admin.entity.RoleEntity;
import com.auth.security.auth_security_app.admin.service.Interface.RoleService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/admin/roles")
public class RoleController {

    private final RoleService service;

    public RoleController(RoleService service) {
        this.service = service;
    }

    @PostMapping
    public ResponseEntity<RoleEntity> create(@RequestBody RoleRequest req) {
        return ResponseEntity.ok(service.createRole(req));
    }

    @GetMapping
    public ResponseEntity<List<RoleEntity>> all() {
        return ResponseEntity.ok(service.getAllRoles());
    }

    @PutMapping("/{id}")
    public ResponseEntity<RoleEntity> update(
            @PathVariable Integer id,
            @RequestBody RoleRequest req
    ) {
        return ResponseEntity.ok(service.updateRole(id, req));
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> delete(@PathVariable Integer id) {
        service.deleteRole(id);
        return ResponseEntity.noContent().build();
    }
}
