package com.auth.security.auth_security_app.admin.service.Implementation;

import com.auth.security.auth_security_app.admin.dto.userRoleDTO.AssignUserRoleDTO;
import com.auth.security.auth_security_app.admin.entity.RoleEntity;
import com.auth.security.auth_security_app.admin.entity.UserEntity;
import com.auth.security.auth_security_app.admin.entity.UserRoleEntity;
import com.auth.security.auth_security_app.admin.repository.RoleRepository;
import com.auth.security.auth_security_app.admin.repository.UserRepository;
import com.auth.security.auth_security_app.admin.repository.UserRoleRepository;
import com.auth.security.auth_security_app.admin.service.Interface.UserRoleService;
import jakarta.persistence.EntityNotFoundException;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserRoleServiceImpl implements UserRoleService {

    private final UserRoleRepository userRoleRepository;
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;



    @Override
    @Transactional
    public String assignUserRole(AssignUserRoleDTO assignUserRoleDTO) {

        UserEntity user=userRepository.findById(assignUserRoleDTO.getUserId())
                                                    .orElseThrow(()-> new UsernameNotFoundException("user ID: "+ assignUserRoleDTO.getUserId()+" not found"));

        RoleEntity role=roleRepository.findById(assignUserRoleDTO.getRoleId())
                .orElseThrow(()-> new EntityNotFoundException("Role ID: "+ assignUserRoleDTO.getRoleId()+" not found"));

        UserRoleEntity userRole=new UserRoleEntity();
        userRole.setRole(role);
        userRole.setUser(user);

        userRoleRepository.save(userRole);

        return "new role: "+role.getRoleName()+" added for user: "+user.getUsername();
    }
}
