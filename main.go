package main

import (
	"context"
	"fmt"
	"os"

	"log/slog"

	"github.com/shanduur/dis-vulncheck/config"
	"github.com/shanduur/dis-vulncheck/output"
	"github.com/shanduur/dis-vulncheck/report"
	"github.com/spf13/afero"
)

func main() {
	ctx := context.Background()

	cliArgs := config.GetCliArgs()

	failures, err := run(ctx, cliArgs)
	if err != nil {
		exitWithError(ctx, cliArgs.Verbose, err)
	}

	fmt.Println("dis-vulncheck scan complete! 🚀")

	if failures > 0 {
		os.Exit(1)
	}

	os.Exit(0)
}

func run(ctx context.Context, cliArgs *config.CliArgs) (int, error) {
	if !cliArgs.Verbose {
		prev := slog.Default()
		slog.SetDefault(slog.New(slog.DiscardHandler))
		defer slog.SetDefault(prev)
	}

	slog.InfoContext(ctx, "running dis-vulncheck")

	fs := afero.NewOsFs()

	cfg, err := config.Get(ctx, cliArgs, fs)
	if err != nil {
		slog.ErrorContext(ctx, "unable to load config", "error", err)
		return 0, fmt.Errorf("unable to load config: %v", err)
	}

	slog.InfoContext(ctx, "configuration set", "config", cfg)

	vulnerabilityReport, err := report.Generate(ctx, cfg)
	if err != nil {
		slog.ErrorContext(ctx, "unable to generate report", "error", err)
		return 0, fmt.Errorf("unable to generate report: %v", err)
	}

	textReport := vulnerabilityReport.GetTextReport(ctx)

	fmt.Println(textReport)

	slog.InfoContext(ctx, "complete", "output", vulnerabilityReport)

	return vulnerabilityReport.Results.Failures, nil
}

// exitWithError prints errors to the command line when the tool has failed to execute
func exitWithError(_ context.Context, verbose bool, err error) {
	output.Error("dis-vulncheck has experienced an unexpected error")
	fmt.Printf("Error was: %s\n", err.Error())
	if !verbose {
		output.Error("run again in verbose mode (--verbose) for more details")
	}
	os.Exit(1)
}
