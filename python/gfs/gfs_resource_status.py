import xml.etree.ElementTree as ET
import json
from sh import pcs
from ablestack import *


def parse_and_serialize_resources():
    try:
        # Fetch XML from pcs command
        xml_string = pcs('status', 'xml')
        root = ET.fromstring(xml_string)

        # List to store resources categorized by nodes
        categorized_resources = {
            "fence_resources": [],
            "glue_locking_resources": [],
            "glue_gfs_resources": []
        }

        # Node history data
        node_history_data = []

        # Parse resources
        node_resources = {}
        nodes_info = []

        # Collect node info
        for node in root.findall(".//nodes/node"):
            node_attributes = {attr: node.get(attr) for attr in node.keys()}
            nodes_info.append(node_attributes)

        # Collect node history
        for node in root.findall(".//node_history/node"):
            node_name = node.get("name")
            resource_histories = []
            for resource in node.findall(".//resource_history"):
                resource_id = resource.get("id")
                operations = []

                # Collect operations and count probes
                seen_calls = set()
                probe_operations = []
                for operation in resource.findall(".//operation_history"):
                    operation_data = {attr: operation.get(attr) for attr in operation.keys()}
                    if operation_data["task"] == "probe":
                        probe_operations.append(operation_data)
                    elif operation_data["call"] not in seen_calls:
                        seen_calls.add(operation_data["call"])
                        operations.append(operation_data)

                # Process probe operations
                if len(probe_operations) > 1:
                    operations.append(probe_operations[0])
                elif len(probe_operations) == 1:
                    # If only one probe, do not include it
                    pass

                resource_histories.append({
                    "resource_id": resource_id,
                    "operations": operations
                })
            node_history_data.append({
                "node_name": node_name,
                "resource_histories": resource_histories
            })
        # Parse main resource list
        for i,resource in enumerate(root.findall(".//resource")):
            resource_id = resource.get("id")

            attributes = {attr: resource.get(attr) for attr in resource.keys()}
            if resource_id.startswith("fence-ablecube"):
                node_name = nodes_info[i-1]["name"]
                fence_resource = attributes.copy()
                fence_resource["node_name"] = node_name  # Add node name from nodes_info
                categorized_resources["fence_resources"].append(fence_resource)

            # Fetch associated nodes for each resource
            for node in resource.findall(".//node"):
                node_name = node.get("name", "unknown")
                if node_name not in node_resources:
                    node_resources[node_name] = {
                        "glue_locking_resources": [],
                        "glue_gfs_resources": []
                    }

                # Handle other resource types
                if resource_id in ["glue-dlm", "glue-lvmlockd"]:
                    node_resources[node_name]["glue_locking_resources"].append(attributes)
                elif resource_id.startswith("glue-gfs"):
                    node_resources[node_name]["glue_gfs_resources"].append(attributes)

        # Serialize the resources to JSON
        result = {
            "nodes_info": nodes_info,
            "resources": categorized_resources,
            "node_history": node_history_data
        }
        ret = createReturn(code=200, val=result)
        return print(json.dumps(json.loads(ret), indent=4))

    except Exception as e:
        ret = createReturn(code=500, val="PCS Not Configured")
        return print(json.dumps(json.loads(ret), indent=4))

# Execute the function and print JSON output
if __name__ == "__main__":
    parse_and_serialize_resources()