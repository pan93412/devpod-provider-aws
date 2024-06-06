package aws

import (
	"context"
	"encoding/base64"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsConfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/loft-sh/devpod-provider-aws/pkg/options"
	"github.com/loft-sh/devpod/pkg/client"
	"github.com/loft-sh/devpod/pkg/log"
	"github.com/loft-sh/devpod/pkg/ssh"
	"github.com/pkg/errors"
)

// detect if we're in an ec2 instance
func isEC2Instance() bool {
	client := &http.Client{}
	req, err := http.NewRequest("GET", "http://instance-data.ec2.internal", nil)
	if err != nil {
		return false
	}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	return true
}

func NewProvider(ctx context.Context, logs log.Logger) (*AwsProvider, error) {
	config, err := options.FromEnv(false)
	if err != nil {
		return nil, err
	}

	cfg, err := awsConfig.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, err
	}

	isEC2 := isEC2Instance()

	if config.DiskImage == "" && !isEC2 {
		image, err := GetDefaultAMI(ctx, cfg, config.MachineType)
		if err != nil {
			return nil, err
		}

		config.DiskImage = image
	}

	if config.RootDevice == "" && !isEC2 {
		device, err := GetAMIRootDevice(ctx, cfg, config.DiskImage)
		if err != nil {
			return nil, err
		}
		config.RootDevice = device
	}

	// create provider
	provider := &AwsProvider{
		Config:    config,
		AwsConfig: cfg,
		Log:       logs,
	}

	return provider, nil
}

type AwsProvider struct {
	Config           *options.Options
	AwsConfig        aws.Config
	Log              log.Logger
	WorkingDirectory string
}

func GetSubnetID(ctx context.Context, provider *AwsProvider) (string, error) {
	svc := ec2.NewFromConfig(provider.AwsConfig)

	// first search for a default devpod specific subnet, if it fails
	// we search the subnet with most free IPs that can do also public-ipv4
	input := &ec2.DescribeSubnetsInput{
		Filters: []types.Filter{
			{
				Name: aws.String("tag:devpod"),
				Values: []string{
					"devpod",
				},
			},
		},
	}

	result, err := svc.DescribeSubnets(ctx, input)
	if err != nil {
		return "", err
	}

	if len(result.Subnets) > 0 {
		return *result.Subnets[0].SubnetId, nil
	}

	input = &ec2.DescribeSubnetsInput{
		Filters: []types.Filter{
			{
				Name: aws.String("vpc-id"),
				Values: []string{
					provider.Config.VpcID,
				},
			},
			{
				Name: aws.String("map-public-ip-on-launch"),
				Values: []string{
					"true",
				},
			},
		},
	}

	result, err = svc.DescribeSubnets(ctx, input)
	if err != nil {
		return "", err
	}

	var maxIPCount int32

	subnetID := ""

	for _, v := range result.Subnets {
		if *v.AvailableIpAddressCount > maxIPCount {
			maxIPCount = *v.AvailableIpAddressCount
			subnetID = *v.SubnetId
		}
	}

	return subnetID, nil
}

func GetDevpodVPC(ctx context.Context, provider *AwsProvider) (string, error) {
	if provider.Config.VpcID != "" {
		return provider.Config.VpcID, nil
	}
	// Get a list of VPCs so we can associate the group with the first VPC.
	svc := ec2.NewFromConfig(provider.AwsConfig)

	result, err := svc.DescribeVpcs(ctx, nil)
	if err != nil {
		return "", err
	}

	if len(result.Vpcs) == 0 {
		return "", errors.New("There are no VPCs to associate with")
	}

	// We need to find a default vpc
	for _, vpc := range result.Vpcs {
		if *vpc.IsDefault {
			return *vpc.VpcId, nil
		}
	}

	return "", nil
}

func GetDefaultAMI(ctx context.Context, cfg aws.Config, instanceType string) (string, error) {
	svc := ec2.NewFromConfig(cfg)

	architecture := "x86_64"
	// Graviton instances terminate with g
	if strings.HasSuffix(strings.Split(instanceType, ".")[0], "g") {
		architecture = "arm64"
	}

	input := &ec2.DescribeImagesInput{
		Owners: []string{
			"amazon",
			"self",
		},
		Filters: []types.Filter{
			{
				Name: aws.String("virtualization-type"),
				Values: []string{
					"hvm",
				},
			},
			{
				Name: aws.String("architecture"),
				Values: []string{
					architecture,
				},
			},
			{
				Name: aws.String("root-device-type"),
				Values: []string{
					"ebs",
				},
			},
			{
				Name: aws.String("platform-details"),
				Values: []string{
					"Linux/UNIX",
				},
			},
			{
				Name: aws.String("description"),
				Values: []string{
					"Canonical, Ubuntu, 22.04 LTS*",
				},
			},
		},
	}

	result, err := svc.DescribeImages(ctx, input)
	if err != nil {
		return "", err
	}

	// Sort by date, so we take the latest AMI available for Ubuntu 22.04
	sort.Slice(result.Images, func(i, j int) bool {
		iTime, err := time.Parse("2006-01-02T15:04:05.000Z", *result.Images[i].CreationDate)
		if err != nil {
			return false
		}
		jTime, err := time.Parse("2006-01-02T15:04:05.000Z", *result.Images[j].CreationDate)
		if err != nil {
			return false
		}

		return iTime.After(jTime)
	})

	return *result.Images[0].ImageId, nil
}

func GetAMIRootDevice(ctx context.Context, cfg aws.Config, diskImage string) (string, error) {
	svc := ec2.NewFromConfig(cfg)

	input := &ec2.DescribeImagesInput{
		ImageIds: []string{
			diskImage,
		},
	}
	result, err := svc.DescribeImages(ctx, input)
	if err != nil {
		return "", err
	}

	// Struct spec: https://docs.aws.amazon.com/sdk-for-go/api/service/ec2/#Image
	if len(result.Images) == 0 || *result.Images[0].RootDeviceName == "" {
		return "/dev/sda1", nil
	}

	return *result.Images[0].RootDeviceName, nil
}

func GetDevpodInstanceProfile(ctx context.Context, provider *AwsProvider) (string, error) {
	if provider.Config.InstanceProfileArn != "" {
		return provider.Config.InstanceProfileArn, nil
	}

	svc := iam.NewFromConfig(provider.AwsConfig)

	roleInput := &iam.GetInstanceProfileInput{
		InstanceProfileName: aws.String("devpod-ec2-role"),
	}

	response, err := svc.GetInstanceProfile(ctx, roleInput)
	if err != nil {
		return CreateDevpodInstanceProfile(ctx, provider)
	}

	return *response.InstanceProfile.Arn, nil
}

func CreateDevpodInstanceProfile(ctx context.Context, provider *AwsProvider) (string, error) {
	svc := iam.NewFromConfig(provider.AwsConfig)
	roleInput := &iam.CreateRoleInput{
		AssumeRolePolicyDocument: aws.String(`{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "Service": "ec2.amazonaws.com"
            },
            "Action": "sts:AssumeRole"
        }
    ]
}`),
		RoleName: aws.String("devpod-ec2-role"),
	}

	_, err := svc.CreateRole(ctx, roleInput)
	if err != nil {
		return "", err
	}

	policyInput := &iam.PutRolePolicyInput{
		PolicyDocument: aws.String(`{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "Describe",
      "Action": [
        "ec2:DescribeInstances"
      ],
      "Effect": "Allow",
      "Resource": "*"
    },
    {
      "Sid": "Stop",
      "Action": [
        "ec2:StopInstances"
      ],
      "Effect": "Allow",
      "Resource": "arn:aws:ec2:*:*:instance/*",
      "Condition": {
        "StringLike": {
          "aws:userid": "*:${ec2:InstanceID}"
        }
      }
    }
  ]
}`),
		PolicyName: aws.String("devpod-ec2-policy"),
		RoleName:   aws.String("devpod-ec2-role"),
	}

	_, err = svc.PutRolePolicy(ctx, policyInput)
	if err != nil {
		return "", err
	}

	instanceProfile := &iam.CreateInstanceProfileInput{
		InstanceProfileName: aws.String("devpod-ec2-role"),
	}

	response, err := svc.CreateInstanceProfile(ctx, instanceProfile)
	if err != nil {
		return "", err
	}

	instanceRole := &iam.AddRoleToInstanceProfileInput{
		InstanceProfileName: aws.String("devpod-ec2-role"),
		RoleName:            aws.String("devpod-ec2-role"),
	}

	_, err = svc.AddRoleToInstanceProfile(ctx, instanceRole)
	if err != nil {
		return "", err
	}

	// TODO: need to find a better way to ensure
	// role/profile propagation has succeeded
	time.Sleep(time.Second * 10)

	return *response.InstanceProfile.Arn, nil
}

func GetDevpodSecurityGroups(ctx context.Context, provider *AwsProvider) ([]string, error) {
	if provider.Config.SecurityGroupID != "" {
		return strings.Split(provider.Config.SecurityGroupID, ","), nil
	}

	svc := ec2.NewFromConfig(provider.AwsConfig)
	input := &ec2.DescribeSecurityGroupsInput{
		Filters: []types.Filter{
			{
				Name: aws.String("tag:devpod"),
				Values: []string{
					"devpod",
				},
			},
		},
	}

	if provider.Config.VpcID != "" {
		input.Filters = append(input.Filters, types.Filter{
			Name: aws.String("vpc-id"),
			Values: []string{
				provider.Config.VpcID,
			},
		})
	}

	result, err := svc.DescribeSecurityGroups(ctx, input)
	// It it is not created, do it
	if len(result.SecurityGroups) == 0 || err != nil {
		sg, err := CreateDevpodSecurityGroup(ctx, provider)
		if err != nil {
			return nil, err
		}

		return []string{sg}, nil
	}

	sgs := []string{}
	for res := range result.SecurityGroups {
		sgs = append(sgs, *result.SecurityGroups[res].GroupId)
	}

	return sgs, nil
}

func CreateDevpodSecurityGroup(ctx context.Context, provider *AwsProvider) (string, error) {
	var err error

	svc := ec2.NewFromConfig(provider.AwsConfig)

	vpc, err := GetDevpodVPC(ctx, provider)
	if err != nil {
		return "", err
	}

	// Create the security group with the VPC, name, and description.
	result, err := svc.CreateSecurityGroup(ctx, &ec2.CreateSecurityGroupInput{
		GroupName:   aws.String("devpod"),
		Description: aws.String("Default Security Group for DevPod"),
		TagSpecifications: []types.TagSpecification{
			{
				ResourceType: "security-group",
				Tags: []types.Tag{
					{
						Key:   aws.String("devpod"),
						Value: aws.String("devpod"),
					},
				},
			},
		},
		VpcId: aws.String(vpc),
	})
	if err != nil {
		return "", err
	}

	groupID := *result.GroupId

	// Add permissions to the security group
	_, err = svc.AuthorizeSecurityGroupIngress(ctx, &ec2.AuthorizeSecurityGroupIngressInput{
		GroupId: aws.String(groupID),
		IpPermissions: []types.IpPermission{
			{
				IpProtocol: aws.String("tcp"),
				FromPort:   aws.Int32(22),
				ToPort:     aws.Int32(22),
				IpRanges: []types.IpRange{
					{
						CidrIp: aws.String("0.0.0.0/0"),
					},
				},
			},
		},
		TagSpecifications: []types.TagSpecification{
			{
				ResourceType: "security-group-rule",
				Tags: []types.Tag{
					{
						Key:   aws.String("devpod"),
						Value: aws.String("devpod-ingress"),
					},
				},
			},
		},
	})
	if err != nil {
		return "", err
	}

	return groupID, nil
}

// GetDevpodInstance returns the instance with the given name
//
// You should get the instance with GetDevpodInstanceByLaunchTemplate
// if the DevPod is created with a launch template (new approach).
func GetDevpodInstance(
	ctx context.Context,
	cfg aws.Config,
	name string,
) (*ec2.DescribeInstancesOutput, error) {
	svc := ec2.NewFromConfig(cfg)

	input := &ec2.DescribeInstancesInput{
		Filters: []types.Filter{
			{
				Name: aws.String("tag:devpod"),
				Values: []string{
					name,
				},
			},
			{
				Name: aws.String("instance-state-name"),
				Values: []string{
					"pending",
					"running",
					"shutting-down",
					"stopped",
					"stopping",
				},
			},
		},
	}

	result, err := svc.DescribeInstances(ctx, input)
	if err != nil {
		return nil, err
	}

	// Sort slice in order to have the newest result first
	sort.Slice(result.Reservations, func(i, j int) bool {
		return result.Reservations[i].Instances[0].LaunchTime.After(
			*result.Reservations[j].Instances[0].LaunchTime,
		)
	})

	return result, nil
}

func GetDevpodStoppedInstance(
	ctx context.Context,
	cfg aws.Config,
	name string,
) (*ec2.DescribeInstancesOutput, error) {
	svc := ec2.NewFromConfig(cfg)

	input := &ec2.DescribeInstancesInput{
		Filters: []types.Filter{
			{
				Name: aws.String("tag:devpod"),
				Values: []string{
					name,
				},
			},
			{
				Name: aws.String("instance-state-name"),
				Values: []string{
					"stopped",
				},
			},
		},
	}

	result, err := svc.DescribeInstances(ctx, input)
	if err != nil {
		return nil, err
	}

	// Sort slice in order to have the newest result first
	sort.Slice(result.Reservations, func(i, j int) bool {
		return result.Reservations[i].Instances[0].LaunchTime.After(
			*result.Reservations[j].Instances[0].LaunchTime,
		)
	})

	return result, nil
}

func GetDevpodRunningInstance(
	ctx context.Context,
	cfg aws.Config,
	name string,
) (*ec2.DescribeInstancesOutput, error) {
	svc := ec2.NewFromConfig(cfg)

	input := &ec2.DescribeInstancesInput{
		Filters: []types.Filter{
			{
				Name: aws.String("tag:devpod"),
				Values: []string{
					name,
				},
			},
			{
				Name: aws.String("instance-state-name"),
				Values: []string{
					"running",
				},
			},
		},
	}

	result, err := svc.DescribeInstances(ctx, input)
	if err != nil {
		return nil, err
	}

	// Sort slice in order to have the newest result first
	sort.Slice(result.Reservations, func(i, j int) bool {
		return result.Reservations[i].Instances[0].LaunchTime.After(
			*result.Reservations[j].Instances[0].LaunchTime,
		)
	})

	return result, nil
}

func GetInstanceTags(providerAws *AwsProvider) []types.LaunchTemplateTagSpecificationRequest {
	result := []types.LaunchTemplateTagSpecificationRequest{
		{
			ResourceType: "instance",
			Tags: []types.Tag{
				{
					Key:   aws.String("devpod"),
					Value: aws.String(providerAws.Config.MachineID),
				},
			},
		},
	}

	reg := regexp.MustCompile(`Name=([A-Za-z0-9!"#$%&'()*+\-./:;<>?@[\\\]^_{|}~]+),Value=([A-Za-z0-9!"#$%&'()*+\-./:;<>?@[\\\]^_{|}~]+)`)

	tagList := reg.FindAllString(providerAws.Config.InstanceTags, -1)
	if tagList == nil {
		return result
	}

	for _, tag := range tagList {
		tagSplit := strings.Split(tag, ",")

		name := strings.ReplaceAll(tagSplit[0], "Name=", "")
		value := strings.ReplaceAll(tagSplit[1], "Value=", "")

		tagSpec := types.Tag{
			Key:   aws.String(name),
			Value: aws.String(value),
		}

		result[0].Tags = append(result[0].Tags, tagSpec)
	}

	return result
}

func Create(
	ctx context.Context,
	cfg aws.Config,
	providerAws *AwsProvider,
) error {
	svc := ec2.NewFromConfig(cfg)

	devpodSG, err := GetDevpodSecurityGroups(ctx, providerAws)
	if err != nil {
		return err
	}

	volSizeI32 := int32(providerAws.Config.DiskSizeGB)

	userData, err := GetInjectKeypairScript(providerAws.Config.MachineFolder)
	if err != nil {
		return err
	}

	// create a launch template for the instance
	launchTemplate := &ec2.CreateLaunchTemplateInput{
		LaunchTemplateData: &types.RequestLaunchTemplateData{
			ImageId:          aws.String(providerAws.Config.DiskImage),
			InstanceType:     types.InstanceType(providerAws.Config.MachineType),
			SecurityGroupIds: devpodSG,
			MetadataOptions: &types.LaunchTemplateInstanceMetadataOptionsRequest{
				HttpEndpoint:            types.LaunchTemplateInstanceMetadataEndpointStateEnabled,
				HttpTokens:              types.LaunchTemplateHttpTokensStateRequired,
				HttpPutResponseHopLimit: aws.Int32(1),
			},
			BlockDeviceMappings: []types.LaunchTemplateBlockDeviceMappingRequest{
				{
					DeviceName: aws.String(providerAws.Config.RootDevice),
					Ebs: &types.LaunchTemplateEbsBlockDeviceRequest{
						VolumeSize: &volSizeI32,
					},
				},
			},
			TagSpecifications: GetInstanceTags(providerAws),
			UserData:          &userData,
		},
		LaunchTemplateName: aws.String(providerAws.Config.MachineID),
	}
	profile, err := GetDevpodInstanceProfile(ctx, providerAws)
	if err == nil {
		launchTemplate.LaunchTemplateData.IamInstanceProfile = &types.LaunchTemplateIamInstanceProfileSpecificationRequest{
			Arn: aws.String(profile),
		}
	}

	result, err := svc.CreateLaunchTemplate(ctx, launchTemplate)
	if err != nil {
		return err
	}

	var instanceBuilder InstanceBuilder
	switch providerAws.Config.UseSpotInstance {
	case true:
		instanceBuilder = NewSpotInstanceBuilder(*result.LaunchTemplate.LaunchTemplateId, providerAws.Config.SubnetID)
	case false:
		instanceBuilder = NewOnDemandInstanceBuilder(*result.LaunchTemplate.LaunchTemplateId, providerAws.Config.SubnetID)
	}

	err = instanceBuilder.Build(ctx, svc)
	if err != nil {
		return err
	}

	return nil
}

func Start(ctx context.Context, cfg aws.Config, instanceID string) error {
	svc := ec2.NewFromConfig(cfg)

	input := &ec2.StartInstancesInput{
		InstanceIds: []string{
			instanceID,
		},
	}

	_, err := svc.StartInstances(ctx, input)
	if err != nil {
		return err
	}

	return err
}

func Stop(ctx context.Context, cfg aws.Config, instanceID string) error {
	svc := ec2.NewFromConfig(cfg)

	input := &ec2.StopInstancesInput{
		InstanceIds: []string{
			instanceID,
		},
	}

	_, err := svc.StopInstances(ctx, input)
	if err != nil {
		return err
	}

	return err
}

func Status(ctx context.Context, cfg aws.Config, name string) (client.Status, error) {
	result, err := GetDevpodInstance(ctx, cfg, name)
	if err != nil {
		return client.StatusNotFound, err
	}

	if len(result.Reservations) == 0 {
		return client.StatusNotFound, nil
	}

	status := result.Reservations[0].Instances[0].State.Name

	switch {
	case status == "running":
		return client.StatusRunning, nil
	case status == "stopped":
		return client.StatusStopped, nil
	case status == "terminated":
		return client.StatusNotFound, nil
	default:
		return client.StatusBusy, nil
	}
}

func Delete(ctx context.Context, cfg aws.Config, instance types.Instance, machineID string) error {
	svc := ec2.NewFromConfig(cfg)

	var deleter InstanceDeleter

	switch instance.InstanceLifecycle {
	case types.InstanceLifecycleTypeSpot:
		deleter = NewSpotInstanceDeleter(*instance.SpotInstanceRequestId)
	default:
		deleter = NewOnDemandInstanceDeleter(*instance.InstanceId)
	}

	err := deleter.Delete(ctx, svc)
	if err != nil {
		return err
	}

	_, err = svc.DeleteLaunchTemplate(ctx, &ec2.DeleteLaunchTemplateInput{
		LaunchTemplateName: aws.String(machineID),
	})
	if err != nil {
		var responseErr types.ResponseError
		if errors.As(err, &responseErr) {
			// fallback: if the launch template does not exist (older instance), we can ignore the error
			if responseErr.Code == types.LaunchTemplateErrorCodeLaunchTemplateNameDoesNotExist {
				return nil
			}
		}

		return err
	}

	return err
}

func GetInjectKeypairScript(dir string) (string, error) {
	publicKeyBase, err := ssh.GetPublicKeyBase(dir)
	if err != nil {
		return "", err
	}

	publicKey, err := base64.StdEncoding.DecodeString(publicKeyBase)
	if err != nil {
		return "", err
	}

	resultScript := `#!/bin/sh
useradd devpod -d /home/devpod
mkdir -p /home/devpod
if grep -q sudo /etc/groups; then
	usermod -aG sudo devpod
elif grep -q wheel /etc/groups; then
	usermod -aG wheel devpod
fi
echo "devpod ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/91-devpod
mkdir -p /home/devpod/.ssh
echo "` + string(publicKey) + `" >> /home/devpod/.ssh/authorized_keys
chmod 0700 /home/devpod/.ssh
chmod 0600 /home/devpod/.ssh/authorized_keys
chown -R devpod:devpod /home/devpod`

	return base64.StdEncoding.EncodeToString([]byte(resultScript)), nil
}
