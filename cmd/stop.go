package cmd

import (
	"context"

	"github.com/loft-sh/devpod-provider-aws/pkg/aws"
	"github.com/pkg/errors"

	"github.com/loft-sh/devpod/pkg/log"
	"github.com/loft-sh/devpod/pkg/provider"
	"github.com/spf13/cobra"
)

// StopCmd holds the cmd flags
type StopCmd struct{}

// NewStopCmd defines a command
func NewStopCmd() *cobra.Command {
	cmd := &StopCmd{}
	stopCmd := &cobra.Command{
		Use:   "stop",
		Short: "Stop an instance",
		RunE: func(_ *cobra.Command, args []string) error {
			awsProvider, err := aws.NewProvider(log.Default)
			if err != nil {
				return err
			}

			return cmd.Run(context.Background(), awsProvider, provider.FromEnvironment(), log.Default)
		},
	}

	return stopCmd
}

// Run runs the command logic
func (cmd *StopCmd) Run(ctx context.Context, provider *aws.AwsProvider, machine *provider.Machine, log log.Logger) error {

	instances, err := aws.GetDevpodRunningInstance(provider.Session, provider.Config.MachineID)
	if err != nil {
		return err
	}

	if len(instances.Reservations) > 0 {
		targetId := instances.Reservations[0].Instances[0].InstanceId
		err = aws.Stop(provider.Session, targetId)
		if err != nil {
			return err
		}
	} else {
		return errors.Errorf("No running instance found")
	}

	return nil
}
