package ndepa.policies

deny[msg] {
    input.kind == "Deployment"
    labels := object.get(input.metadata, "labels", {})
    not labels.env
    msg := sprintf("CUSTOM RULE VIOLATION: Deployment '%s' must have an 'env' label.", [input.metadata.name])
}

# Flag pods running as root user (runAsUser == 0)
deny[msg] {
    input.kind == "Pod"
    container := input.spec.containers[_]
    container.securityContext.runAsUser == 0
    msg := sprintf("CUSTOM RULE VIOLATION: Container '%s' in Pod '%s' runs as root (runAsUser: 0)", [container.name, input.metadata.name])
}

# Flag pods running in privileged mode
deny[msg] {
    input.kind == "Pod"
    container := input.spec.containers[_]
    container.securityContext.privileged == true
    msg := sprintf("CUSTOM RULE VIOLATION: Container '%s' in Pod '%s' runs in privileged mode", [container.name, input.metadata.name])
}
