package cmd

import (
	"fmt"

	"github.com/morikuni/aec"
	"github.com/spf13/cobra"
)

var (
	Version   string
	GitCommit string
)

func PrintK3supASCIIArt() {
	k3supLogo := aec.RedF.Apply(k3supFigletStr)
	fmt.Print(k3supLogo)
}

func MakeVersion() *cobra.Command {
	var command = &cobra.Command{
		Use:          "version",
		Short:        "Print the version",
		Example:      `  k2sup version`,
		SilenceUsage: false,
	}
	command.Run = func(cmd *cobra.Command, args []string) {
		PrintK3supASCIIArt()
		if len(Version) == 0 {
			fmt.Println("Version: dev")
		} else {
			fmt.Println("Version:", Version)
		}
		fmt.Println("Git Commit:", GitCommit)

		fmt.Printf("\n%s\n", SupportMsg)

	}
	return command
}

const k3supFigletStr = ` _    ____
| | _|___ \ ___ _   _ _ __
| |/ / __) / __| | | | '_ \
|   < / __/\__ \ |_| | |_) |
|_|\_\_____|___/\__,_| .__/
                     |_|
`
