import json
import yaml
import argparse

def policy_to_yaml(json_file, yaml_file):
    """Reads a JSON file, converts it to YAML, and writes it to an output file."""
    # Read the JSON file
    with open(json_file, "r") as file:
        json_data = json.load(file)
    
    policies = json_data.get("policies", [])
    yaml_policies = []

    for policy in policies:
        yaml_policy = {
            "kind": "SecurityPolicy",
            "apiVersion": "config.stackrox.io/v1alpha1",
            "metadata": {
                "name": policy["name"].lower().replace(" ", "-")
            },
            "spec": {
                "policyName": policy["name"],
                "description": policy.get("description", ""),                
                "rationale": policy.get("rationale", ""),
                "remediation": policy.get("remediation", ""),
                "categories": policy.get("categories", []),
                "disabled": policy.get("disabled", False),
                "lifecycleStages": policy.get("lifecycleStages", []),
                "eventSource": policy.get("eventSource", []),
                "exclusions": policy.get("exclusions", []),
                "severity": policy.get("severity", []),
                "notifiers": policy.get("notifiers", []),                
                "policySections": policy.get("policySections", []),
                "scope": policy.get("scope", []),
                "mitreAttackVectors": policy.get("mitreAttackVectors", []),
                "criteriaLocked": policy.get("criteriaLocked", []),
                "mitreVectorsLocked": policy.get("mitreVectorsLocked", []),
                "isDefault": policy.get("isDefault", [])
            }
        }
        yaml_policies.append(yaml_policy)

    # Write to YAML file
    with open(yaml_file, "w") as file:
        yaml.dump_all(yaml_policies, file, default_flow_style=False, sort_keys=False)

    print(f"✅ YAML output saved to {yaml_file}")

if __name__ == "__main__":
    # Set up argument parser
    parser = argparse.ArgumentParser(description="Convert StackRox JSON exports to SecurityPolicy YAML")
    parser.add_argument("-i", "--input", required=True, help="Path to the exported JSON file")
    parser.add_argument("-o", "--output", required=True, help="Output file path")
    
    # Parse arguments
    args = parser.parse_args()

    # Convert the policy
    policy_to_yaml(args.input, args.output)