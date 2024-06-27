#!/bin/bash

# Step 1: Get the rabbitmq password
PASSWORD=$(kubectl get secret defectdojo-rabbitmq-specific -n defectdojo -o jsonpath="{.data.rabbitmq-password}" | base64 --decode)

# Step 2: Execute the command in the defectdojo-rabbitmq-0 pod
kubectl exec -it defectdojo-rabbitmq-0 -n defectdojo -- /bin/bash -c "
    # Step 3: Change the rabbitmq password
    rabbitmqctl change_password user $PASSWORD
"

# Step 4: Restart the stateful set
kubectl rollout restart statefulset defectdojo-rabbitmq -n defectdojo
