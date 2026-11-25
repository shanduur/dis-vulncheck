package config

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"regexp"
	"strings"
	"time"

	"log/slog"

	"github.com/goccy/go-yaml"
	"github.com/shanduur/dis-vulncheck/output"
	"github.com/spf13/afero"
)

const DefaultIgnoreTTL = 7 * 24 * time.Hour // 7 days

type CliArgs struct {
	BuildTags      string `json:"build-tags,omitempty"`
	ConfigFilePath string `json:"config,omitempty"`
	Verbose        bool   `json:"verbose,omitempty"`
	Tool           bool   `json:"tool,omitempty"`
}

type UserConfig struct {
	Ignore      []IgnoreStatement `yaml:"ignore"`
	GoToolChain string            `yaml:"toolchain"`
	IgnoreTTL   *time.Duration    `yaml:"ignore_ttl"`
}

// GetIgnoreTTL returns the configured TTL or the default of 7 days.
func (c *UserConfig) GetIgnoreTTL() time.Duration {
	if c.IgnoreTTL != nil {
		return *c.IgnoreTTL
	}
	return DefaultIgnoreTTL
}

type Config struct {
	BuildTags   string
	GoToolChain string
	UseTool     bool
	UserConfig  *UserConfig
}

type IgnoreStatement struct {
	ID      string    `yaml:"id"`
	Reason  string    `yaml:"reason"`
	Date    time.Time `yaml:"date"`
	Matched bool
}

var (
	configFileNames []string = []string{
		".dis-vulncheck.yml",
		".dis-vulncheck.yaml",
		".disvulncheck.yml",
		".disvulncheck.yaml",
	}
	defaultCIBuildFilePath = "./ci/build.yml"
)

func getGoToolChain(ctx context.Context, userCfg *UserConfig, fs afero.Fs) string {
	CIBuildVersion, err := getCIGoBuildVersion(ctx, defaultCIBuildFilePath, fs)
	if err != nil {
		slog.ErrorContext(ctx, "couldn't load build version from CI files - allowing Go toolchain to default", "error", err)
	}

	if userCfg.GoToolChain != "" {
		if CIBuildVersion != "" {
			message := fmt.Sprintf(
				"You have overridden the Go toolchain version - your config file is set to %s but the build version is %s",
				userCfg.GoToolChain,
				CIBuildVersion,
			)
			output.Warn(message)
		}

		return userCfg.GoToolChain
	}

	return CIBuildVersion
}

func getCIGoBuildVersion(ctx context.Context, filepath string, fs afero.Fs) (string, error) {
	var ciBuild struct {
		Platform string `yaml:"platform"`
		ImRes    struct {
			Source struct {
				Repository string `yaml:"repository"`
				Tag        string `yaml:"tag"`
			} `yaml:"source"`
		} `yaml:"image_resource"`
	}

	buildBytes, err := afero.ReadFile(fs, filepath)
	if err != nil {
		slog.ErrorContext(ctx, "unable to read ci build file", "error", err)
		return "", err
	}

	err = yaml.Unmarshal(buildBytes, &ciBuild)
	if err != nil {
		slog.ErrorContext(ctx, "unable to unmarshal ci build file yaml", "error", err)
		return "", err
	}

	if ciBuild.ImRes.Source.Tag != "" {
		version := strings.Split(ciBuild.ImRes.Source.Tag, "-")[0]
		r := regexp.MustCompile(`^\d+.\d+.\d+$`)

		if r.MatchString(version) {
			return fmt.Sprintf("go%s", version), nil
		}
	}

	return "", errors.New("no tag returned")
}

func pickUserConfigFile(ctx context.Context, cliArgs *CliArgs, fs afero.Fs) (string, error) {
	if cliArgs.ConfigFilePath != "" {
		if _, err := fs.Stat(cliArgs.ConfigFilePath); err == nil {
			return cliArgs.ConfigFilePath, nil
		} else {
			slog.ErrorContext(ctx, "error finding custom config file", "error", err, "filepath", cliArgs.ConfigFilePath)
			return "", err
		}
	} else {
		for _, filename := range configFileNames {
			if _, err := fs.Stat(filename); err == nil {
				return filename, nil
			}
		}
		slog.InfoContext(ctx, "no default config files available")
	}
	// No user config file is acceptable
	return "", nil
}

func getUserConfig(ctx context.Context, cliArgs *CliArgs, fs afero.Fs) (*UserConfig, error) {
	var cfg UserConfig

	configFileName, err := pickUserConfigFile(ctx, cliArgs, fs)
	if err != nil {
		slog.InfoContext(ctx, "couldn't get a user config file", "filename", configFileName)
		return &UserConfig{}, err
	}

	// If no config, just return nothing
	if configFileName == "" {
		return &UserConfig{}, nil
	}

	slog.InfoContext(ctx, "getting config from file", "filename", configFileName)

	configBytes, err := afero.ReadFile(fs, configFileName)
	if err != nil {
		slog.ErrorContext(ctx, "unable to read config file", "error", err)
		return &UserConfig{}, err
	}

	err = yaml.Unmarshal(configBytes, &cfg)
	if err != nil {
		slog.ErrorContext(ctx, "unable to unmarshal config file yaml", "error", err)
		return &UserConfig{}, err
	}

	return &cfg, nil
}

// GetCliArgs parses the cli arguments passed.
func GetCliArgs() *CliArgs {
	var cliArgs CliArgs

	flag.StringVar(&cliArgs.BuildTags, "build-tags", "", "build tags for govulncheck")
	flag.StringVar(&cliArgs.ConfigFilePath, "config", "", "config filepath")
	flag.BoolVar(&cliArgs.Verbose, "verbose", false, "run tool in verbose mode or not")
	flag.BoolVar(&cliArgs.Tool, "tool", true, "use govulncheck via go tool (true) or from PATH (false)")
	flag.Parse()

	return &cliArgs
}

// Get will retrieve the userConfig and the Go Toolchain.
func Get(ctx context.Context, cliArgs *CliArgs, fs afero.Fs) (*Config, error) {
	userConfig, err := getUserConfig(ctx, cliArgs, fs)
	if err != nil {
		slog.ErrorContext(ctx, "unable to load config", "error", err)
		return nil, fmt.Errorf("unable to load config: %v", err)
	}

	goToolchain := getGoToolChain(ctx, userConfig, fs)

	cfg := Config{
		BuildTags:   cliArgs.BuildTags,
		GoToolChain: goToolchain,
		UseTool:     cliArgs.Tool,
		UserConfig:  userConfig,
	}

	slog.InfoContext(ctx, "config", "config", cfg)

	return &cfg, err
}
