# ... existing code ...

detach-instance:
	@echo "Detaching instance $(INSTANCE_ID) from ASG"
	aws autoscaling detach-instances --instance-ids $(INSTANCE_ID) --auto-scaling-group-name $(ASG_NAME) --should-decrement-desired-capacity
	@echo "Restoring ASG $(ASG_NAME) to desired capacity"
	desired_capacity=$(shell aws autoscaling describe-auto-scaling-groups --auto-scaling-group-names $(ASG_NAME) --query "AutoScalingGroups[0].DesiredCapacity" --output text)
	aws autoscaling update-auto-scaling-group --auto-scaling-group-name $(ASG_NAME) --desired-capacity $$desired_capacity

# ... existing code ... 