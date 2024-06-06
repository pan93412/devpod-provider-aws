package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

type InstanceBuilder interface {
	Build(ctx context.Context, svc *ec2.Client) error
}

type InstanceDeleter interface {
	Delete(ctx context.Context, svc *ec2.Client) error
}

type OnDemandInstanceBuilder struct {
	runInstanceInput *ec2.RunInstancesInput
}

type OnDemandInstanceDeleter struct {
	instanceID string
}

func NewOnDemandInstanceBuilder(launchTemplateName string, subnetID string) *OnDemandInstanceBuilder {
	return &OnDemandInstanceBuilder{
		runInstanceInput: &ec2.RunInstancesInput{
			LaunchTemplate: &types.LaunchTemplateSpecification{
				LaunchTemplateName: &launchTemplateName,
				Version:            aws.String("$Latest"),
			},
			SubnetId: aws.String(subnetID),
		},
	}
}

func NewOnDemandInstanceDeleter(instanceID string) *OnDemandInstanceDeleter {
	return &OnDemandInstanceDeleter{
		instanceID: instanceID,
	}
}

func (r *OnDemandInstanceBuilder) Build(ctx context.Context, svc *ec2.Client) error {
	_, err := svc.RunInstances(ctx, r.runInstanceInput)
	return err
}

func (r *OnDemandInstanceDeleter) Delete(ctx context.Context, svc *ec2.Client) error {
	_, err := svc.TerminateInstances(ctx, &ec2.TerminateInstancesInput{
		InstanceIds: []string{r.instanceID},
	})
	return err
}

type SpotInstanceBuilder struct {
	createFleetInput *ec2.CreateFleetInput
}

type SpotInstanceDeleter struct {
	fleetID string
}

func NewSpotInstanceBuilder(launchTemplateName string, subnetID string) *SpotInstanceBuilder {
	return &SpotInstanceBuilder{
		createFleetInput: &ec2.CreateFleetInput{
			LaunchTemplateConfigs: []types.FleetLaunchTemplateConfigRequest{
				{
					LaunchTemplateSpecification: &types.FleetLaunchTemplateSpecificationRequest{
						LaunchTemplateName: &launchTemplateName,
						Version:            aws.String("$Latest"),
					},
					Overrides: []types.FleetLaunchTemplateOverridesRequest{
						{
							SubnetId: aws.String(subnetID),
						},
					},
				},
			},
			SpotOptions: &types.SpotOptionsRequest{
				InstancePoolsToUseCount: aws.Int32(1),
				AllocationStrategy:      types.SpotAllocationStrategyPriceCapacityOptimized,
			},
			TargetCapacitySpecification: &types.TargetCapacitySpecificationRequest{
				TotalTargetCapacity:       aws.Int32(1),
				DefaultTargetCapacityType: types.DefaultTargetCapacityTypeSpot,
			},
			Type: types.FleetTypeInstant,
		},
	}
}

func NewSpotInstanceDeleter(fleetID string) *SpotInstanceDeleter {
	return &SpotInstanceDeleter{
		fleetID: fleetID,
	}
}

func (c *SpotInstanceBuilder) Build(ctx context.Context, svc *ec2.Client) error {
	_, err := svc.CreateFleet(ctx, c.createFleetInput)
	return err
}

func (c *SpotInstanceDeleter) Delete(ctx context.Context, svc *ec2.Client) error {
	_, err := svc.DeleteFleets(ctx, &ec2.DeleteFleetsInput{
		FleetIds:           []string{c.fleetID},
		TerminateInstances: aws.Bool(true),
	})
	return err
}
