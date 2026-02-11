package com.auth.security.auth_security_app.admin.service.Implementation;

import com.auth.security.auth_security_app.admin.dto.permissionDTO.PermissionRequestDTO;
import com.auth.security.auth_security_app.admin.dto.permissionDTO.PermissionResponseDTO;
import com.auth.security.auth_security_app.admin.entity.PermissionEntity;
import com.auth.security.auth_security_app.admin.repository.PermissionRepository;
import com.auth.security.auth_security_app.admin.service.Interface.PermissionService;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
public class PermissionServiceImpl implements PermissionService {

    private final PermissionRepository permissionRepository;

    /* ============================================================
       CREATE
       ============================================================ */
    @Override
    public PermissionResponseDTO create(PermissionRequestDTO request) {

        if (permissionRepository.existsByPermissionName(request.getPermissionName())) {
            throw new RuntimeException("Permission name already exists");
        }

        PermissionEntity p = PermissionEntity.builder()
                .permissionName(request.getPermissionName())
                .description(request.getDescription())
                .build();

        return toDTO(permissionRepository.save(p));
    }

    /* ============================================================
       UPDATE
       ============================================================ */
    @Override
    public PermissionResponseDTO update(Long permissionId, PermissionRequestDTO request) {

        PermissionEntity p = permissionRepository.findById(permissionId)
                .orElseThrow(() -> new RuntimeException("Permission not found"));

        p.setPermissionName(request.getPermissionName());
        p.setDescription(request.getDescription());

        return toDTO(permissionRepository.save(p));
    }

    /* ============================================================
       DELETE
       ============================================================ */
    @Override
    public String delete(Long permissionId) {
        permissionRepository.deleteById(permissionId);
        return "Permission deleted";
    }

    /* ============================================================
       GET ALL
       ============================================================ */
    @Override
    public List<PermissionResponseDTO> getAll() {
        return permissionRepository.findAll()
                .stream()
                .map(this::toDTO)
                .toList();
    }

    /* ============================================================
       GET BY ID
       ============================================================ */
    @Override
    public PermissionResponseDTO getById(Long permissionId) {
        PermissionEntity p = permissionRepository.findById(permissionId)
                .orElseThrow(() -> new RuntimeException("Permission not found"));
        return toDTO(p);
    }

    /* ============================================================
       ENTITY → DTO MAPPER
       ============================================================ */
    private PermissionResponseDTO toDTO(PermissionEntity p) {

        PermissionResponseDTO dto = new PermissionResponseDTO();
        dto.setId(p.getPerm_id());
        dto.setPermissionName(p.getPermissionName());
        dto.setDescription(p.getDescription());

        return dto;
    }
}
