package com.alibou.security.services.impl;

import lombok.RequiredArgsConstructor;

import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import com.alibou.security.models.Project;
import com.alibou.security.payload.response.ProjectDto;
import com.alibou.security.repository.ProjectRepository;
import com.alibou.security.services.ProjectService;

import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class ProjectServiceImpl implements ProjectService {

    @Autowired
    private final ProjectRepository repo;

    public void save(Project project) {
        System.out.println("Save Called");
    }

    public List<ProjectDto> findAll() {
        List<Project> projects = repo.findAll();
        List<ProjectDto> projectDtoList = mapList(projects, ProjectDto.class);
        return projectDtoList;
    }

    <S, T> List<T> mapList(List<S> source, Class<T> targetClass) {
        ModelMapper modelMapper = new ModelMapper();
        return source
                .stream()
                .map(element -> modelMapper.map(element, targetClass))
                .collect(Collectors.toList());
    }

}
