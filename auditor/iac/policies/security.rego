package main

# Project controls supplement Checkov's upstream infrastructure rules. Keep
# control IDs and metadata stable; the normalizer preserves these IDs verbatim.

terraform_bucket(name) := bucket if {
	bucket := input.resource.aws_s3_bucket[name][0]
}

terraform_bucket(name) := bucket if {
	bucket := input.resource.aws_s3_bucket[name]
	is_object(bucket)
}

deny contains violation if {
	some name
	input.resource.aws_s3_bucket[name]
	bucket := terraform_bucket(name)
	bucket.acl == "public-read"
	violation := {
		"msg": "S3 buckets must not grant public read access through an ACL.",
		"metadata": {
			"control_id": "IAC-TF-001",
			"severity": "HIGH",
			"title": "S3 bucket ACL grants public read access",
			"remediation": "Remove the public ACL and configure S3 Block Public Access.",
			"resource_reference": sprintf("aws_s3_bucket.%s", [name]),
		},
	}
}

pod_spec := input.spec if {
	input.kind == "Pod"
}

pod_spec := input.spec.template.spec if {
	input.kind in {"Deployment", "DaemonSet", "StatefulSet", "ReplicaSet"}
}

pod_spec := input.spec.jobTemplate.spec.template.spec if {
	input.kind == "CronJob"
}

pod_spec := input.spec.template.spec if {
	input.kind == "Job"
}

pod_container := pod_spec.containers[_] if {
	count(pod_spec.containers) > 0
}

pod_container := pod_spec.initContainers[_] if {
	count(pod_spec.initContainers) > 0
}

kubernetes_resource := sprintf("%s/%s", [input.kind, input.metadata.name]) if {
	is_string(input.kind)
	is_string(input.metadata.name)
}

kubernetes_resource := input.kind if {
	is_string(input.kind)
	not input.metadata.name
}

host_namespace_enabled if {
	pod_spec.hostNetwork == true
}

host_namespace_enabled if {
	pod_spec.hostPID == true
}

host_namespace_enabled if {
	pod_spec.hostIPC == true
}

deny contains violation if {
	input.apiVersion
	pod_container.securityContext.privileged == true
	violation := {
		"msg": "Containers must not run in privileged mode.",
		"metadata": {
			"control_id": "IAC-K8S-001",
			"severity": "HIGH",
			"title": "Privileged container",
			"remediation": "Set securityContext.privileged to false or remove it.",
			"resource_reference": kubernetes_resource,
		},
	}
}

deny contains violation if {
	input.apiVersion
	pod_container.image
	endswith(pod_container.image, ":latest")
	violation := {
		"msg": "Container images must not use the mutable latest tag.",
		"metadata": {
			"control_id": "IAC-K8S-002",
			"severity": "MEDIUM",
			"title": "Container image uses latest tag",
			"remediation": "Pin the image to a reviewed version tag or immutable digest.",
			"resource_reference": kubernetes_resource,
		},
	}
}

deny contains violation if {
	input.apiVersion
	host_namespace_enabled
	violation := {
		"msg": "Pod workloads must not share host network, process, or IPC namespaces.",
		"metadata": {
			"control_id": "IAC-K8S-003",
			"severity": "HIGH",
			"title": "Pod shares a host namespace",
			"remediation": "Set hostNetwork, hostPID, and hostIPC to false.",
			"resource_reference": kubernetes_resource,
		},
	}
}
