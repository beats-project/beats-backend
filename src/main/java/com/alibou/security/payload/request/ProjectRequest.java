package com.alibou.security.payload.request;

import java.time.LocalDateTime;

import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Builder
public class ProjectRequest {

    private Integer id;
    private String name;
    private String description;
    private LocalDateTime dueDate;

    private String ownerId;
}
