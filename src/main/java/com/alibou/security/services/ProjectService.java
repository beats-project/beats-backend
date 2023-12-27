package com.alibou.security.services;

import java.util.List;

import com.alibou.security.models.Project;
import com.alibou.security.payload.response.ProjectDto;

public interface ProjectService {
    public void save(Project project);

    public List<ProjectDto> findAll();
}
