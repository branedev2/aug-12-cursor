package main

import (
	"context"
	"fmt"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/appconfig"
	appconfigagent "github.com/aws/aws-sdk-go-v2/service/appconfigagent"
	"github.com/aws/aws-sdk-go-v2/service/appconfigdata"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/appconfig/appconfigiface"
	oldappconfig "github.com/aws/aws-sdk-go/service/appconfig"
)

// True Positive Examples (Vulnerable Code)

// {fact rule=guru-cfn-lint@v1.0 defects=1}
func bad_case_1() {
	// Initialize AWS session
	sess := session.Must(session.NewSession())
	
	// Create AppConfig client
	svc := oldappconfig.New(sess)
	
	// ruleid: rule-deprecated-get-configuration
	result, err := svc.GetConfiguration(&oldappconfig.GetConfigurationInput{
		Application:   aws.String("MyApp"),
		Environment:   aws.String("Production"),
		Configuration: aws.String("MyConfig"),
		ClientId:      aws.String("MyClientId"),
	})
	
	if err != nil {
		fmt.Println("Error getting configuration:", err)
		return
	}
	
	fmt.Println("Configuration content:", string(result.Content))
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
func bad_case_2() {
	// Initialize AWS session with specific region
	sess := session.Must(session.NewSession(&aws.Config{
		Region: aws.String("us-west-2"),
	}))
	
	// Create AppConfig client
	svc := oldappconfig.New(sess)
	
	// Define input parameters
	input := &oldappconfig.GetConfigurationInput{
		Application:   aws.String("OrderSystem"),
		Environment:   aws.String("Staging"),
		Configuration: aws.String("DatabaseSettings"),
		ClientId:      aws.String("OrderSystemClient"),
	}
	
	// ruleid: rule-deprecated-get-configuration
	result, err := svc.GetConfiguration(input)
	
	if err != nil {
		fmt.Println("Failed to get configuration:", err)
		return
	}
	
	fmt.Println("Retrieved configuration version:", *result.ConfigurationVersion)
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
func bad_case_3() {
	// Initialize AWS session
	sess := session.Must(session.NewSession())
	
	// Create AppConfig client
	appConfigClient := oldappconfig.New(sess)
	
	// Get configuration with retry logic
	var config *oldappconfig.GetConfigurationOutput
	var err error
	
	for i := 0; i < 3; i++ {
		// ruleid: rule-deprecated-get-configuration
		config, err = appConfigClient.GetConfiguration(&oldappconfig.GetConfigurationInput{
			Application:   aws.String("PaymentService"),
			Environment:   aws.String("Production"),
			Configuration: aws.String("ApiKeys"),
			ClientId:      aws.String("PaymentProcessor"),
		})
		
		if err == nil {
			break
		}
		
		fmt.Printf("Attempt %d failed: %v\n", i+1, err)
	}
	
	if err != nil {
		fmt.Println("All attempts to get configuration failed")
		return
	}
	
	fmt.Println("Configuration retrieved successfully")
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
func bad_case_4() {
	// Create a custom AppConfig client interface for testing
	type AppConfigClientInterface interface {
		GetConfiguration(*oldappconfig.GetConfigurationInput) (*oldappconfig.GetConfigurationOutput, error)
	}
	
	// Initialize AWS session
	sess := session.Must(session.NewSession())
	
	// Create AppConfig client that implements the interface
	var client AppConfigClientInterface = oldappconfig.New(sess)
	
	// ruleid: rule-deprecated-get-configuration
	resp, err := client.GetConfiguration(&oldappconfig.GetConfigurationInput{
		Application:   aws.String("NotificationSystem"),
		Environment:   aws.String("Development"),
		Configuration: aws.String("EmailTemplates"),
		ClientId:      aws.String("NotificationClient"),
	})
	
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	
	fmt.Println("Configuration content length:", len(resp.Content))
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
func bad_case_5(appConfigClient *oldappconfig.AppConfig) {
	// Using the deprecated API with a client passed as a parameter
	input := &oldappconfig.GetConfigurationInput{
		Application:   aws.String("UserManagement"),
		Environment:   aws.String("Production"),
		Configuration: aws.String("UserRoles"),
		ClientId:      aws.String("AdminPanel"),
	}
	
	// ruleid: rule-deprecated-get-configuration
	result, err := appConfigClient.GetConfiguration(input)
	
	if err != nil {
		fmt.Println("Failed to retrieve configuration:", err)
		return
	}
	
	fmt.Println("Configuration retrieved, content type:", *result.ContentType)
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
func bad_case_6() {
	// Initialize AWS session with profile
	sess := session.Must(session.NewSessionWithOptions(session.Options{
		Profile: "production",
	}))
	
	// Create AppConfig client
	svc := oldappconfig.New(sess)
	
	// Define configuration parameters
	app := "LoggingService"
	env := "Production"
	config := "LogLevels"
	clientId := "LoggingClient"
	
	// ruleid: rule-deprecated-get-configuration
	result, err := svc.GetConfiguration(&oldappconfig.GetConfigurationInput{
		Application:   &app,
		Environment:   &env,
		Configuration: &config,
		ClientId:      &clientId,
	})
	
	if err != nil {
		fmt.Println("Error getting configuration:", err)
		return
	}
	
	fmt.Println("Configuration retrieved successfully:", string(result.Content))
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
func bad_case_7() {
	// Initialize AWS session
	sess := session.Must(session.NewSession())
	
	// Create AppConfig client with custom endpoint
	svc := oldappconfig.New(sess, &aws.Config{
		Endpoint: aws.String("https://appconfig.us-east-1.amazonaws.com"),
	})
	
	// Create input with client token for idempotency
	input := &oldappconfig.GetConfigurationInput{
		Application:   aws.String("AnalyticsService"),
		Environment:   aws.String("Production"),
		Configuration: aws.String("TrackingConfig"),
		ClientId:      aws.String("AnalyticsClient"),
		ClientConfigurationVersion: aws.String("1"),
	}
	
	// ruleid: rule-deprecated-get-configuration
	config, err := svc.GetConfiguration(input)
	
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	
	fmt.Println("Configuration version:", *config.ConfigurationVersion)
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
func bad_case_8() {
	// Initialize AWS session
	sess := session.Must(session.NewSession())
	
	// Create AppConfig client
	appConfigClient := oldappconfig.New(sess)
	
	// Function to get configuration
	getConfig := func(app, env, config, clientId string) ([]byte, error) {
		// ruleid: rule-deprecated-get-configuration
		result, err := appConfigClient.GetConfiguration(&oldappconfig.GetConfigurationInput{
			Application:   aws.String(app),
			Environment:   aws.String(env),
			Configuration: aws.String(config),
			ClientId:      aws.String(clientId),
		})
		
		if err != nil {
			return nil, err
		}
		
		return result.Content, nil
	}
	
	// Use the function to get configuration
	content, err := getConfig("SearchService", "Production", "SearchSettings", "SearchClient")
	if err != nil {
		fmt.Println("Error getting configuration:", err)
		return
	}
	
	fmt.Println("Configuration content length:", len(content))
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
func bad_case_9() {
	// Initialize AWS session
	sess := session.Must(session.NewSession())
	
	// Create AppConfig client
	svc := oldappconfig.New(sess)
	
	// Define configuration parameters from environment variables
	app := os.Getenv("APP_NAME")
	if app == "" {
		app = "DefaultApp"
	}
	
	env := os.Getenv("APP_ENV")
	if env == "" {
		env = "Development"
	}
	
	config := os.Getenv("CONFIG_NAME")
	if config == "" {
		config = "DefaultConfig"
	}
	
	clientId := "Client-" + app + "-" + env
	
	// ruleid: rule-deprecated-get-configuration
	result, err := svc.GetConfiguration(&oldappconfig.GetConfigurationInput{
		Application:   aws.String(app),
		Environment:   aws.String(env),
		Configuration: aws.String(config),
		ClientId:      aws.String(clientId),
	})
	
	if err != nil {
		fmt.Println("Error getting configuration:", err)
		return
	}
	
	fmt.Println("Configuration content:", string(result.Content))
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
func bad_case_10() {
	// Initialize AWS session
	sess := session.Must(session.NewSession())
	
	// Create AppConfig client with custom configuration
	svc := oldappconfig.New(sess, &aws.Config{
		MaxRetries: aws.Int(5),
		Region:     aws.String("eu-west-1"),
	})
	
	// Define input parameters
	input := &oldappconfig.GetConfigurationInput{
		Application:   aws.String("RecommendationEngine"),
		Environment:   aws.String("Production"),
		Configuration: aws.String("AlgorithmSettings"),
		ClientId:      aws.String("RecommendationClient"),
	}
	
	// ruleid: rule-deprecated-get-configuration
	output, err := svc.GetConfiguration(input)
	
	if err != nil {
		fmt.Println("Failed to get configuration:", err)
		return
	}
	
	// Process the configuration
	if output.ConfigurationVersion != nil {
		fmt.Println("Configuration version:", *output.ConfigurationVersion)
	}
	
	if len(output.Content) > 0 {
		fmt.Println("Configuration content available")
	}
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
func bad_case_11() {
	// Initialize AWS session
	sess := session.Must(session.NewSession())
	
	// Create AppConfig client
	appConfigClient := oldappconfig.New(sess)
	
	// Define a wrapper function for getting configuration
	getAppConfig := func(appName, envName, configName string) ([]byte, string, error) {
		clientId := fmt.Sprintf("%s-%s-client", appName, envName)
		
		// ruleid: rule-deprecated-get-configuration
		resp, err := appConfigClient.GetConfiguration(&oldappconfig.GetConfigurationInput{
			Application:   aws.String(appName),
			Environment:   aws.String(envName),
			Configuration: aws.String(configName),
			ClientId:      aws.String(clientId),
		})
		
		if err != nil {
			return nil, "", err
		}
		
		var version string
		if resp.ConfigurationVersion != nil {
			version = *resp.ConfigurationVersion
		}
		
		return resp.Content, version, nil
	}
	
	// Use the wrapper function
	content, version, err := getAppConfig("CatalogService", "Staging", "ProductCatalog")
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	
	fmt.Printf("Retrieved configuration version %s with %d bytes\n", version, len(content))
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
func bad_case_12() {
	// Initialize AWS session
	sess := session.Must(session.NewSession())
	
	// Create AppConfig client with custom HTTP client
	svc := oldappconfig.New(sess, &aws.Config{
		HTTPClient: &http.Client{
			Timeout: time.Second * 30,
		},
	})
	
	// Define input with a specific client configuration version
	input := &oldappconfig.GetConfigurationInput{
		Application:   aws.String("InventorySystem"),
		Environment:   aws.String("Production"),
		Configuration: aws.String("InventoryRules"),
		ClientId:      aws.String("InventoryClient"),
		ClientConfigurationVersion: aws.String("2.1.0"),
	}
	
	// ruleid: rule-deprecated-get-configuration
	result, err := svc.GetConfiguration(input)
	
	if err != nil {
		fmt.Println("Error getting configuration:", err)
		return
	}
	
	if result.NextPollConfigurationToken != nil {
		fmt.Println("Next poll token:", *result.NextPollConfigurationToken)
	}
	
	fmt.Println("Configuration content size:", len(result.Content))
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
func bad_case_13() {
	// Initialize AWS session
	sess := session.Must(session.NewSession())
	
	// Create AppConfig client
	appConfigClient := oldappconfig.New(sess)
	
	// Define a struct to hold configuration settings
	type ConfigSettings struct {
		AppName    string
		EnvName    string
		ConfigName string
		ClientId   string
	}
	
	// Create settings for different environments
	configs := []ConfigSettings{
		{
			AppName:    "AuthService",
			EnvName:    "Development",
			ConfigName: "AuthSettings",
			ClientId:   "AuthClient-Dev",
		},
		{
			AppName:    "AuthService",
			EnvName:    "Production",
			ConfigName: "AuthSettings",
			ClientId:   "AuthClient-Prod",
		},
	}
	
	// Get configuration for the current environment
	envType := os.Getenv("ENV_TYPE")
	if envType == "" {
		envType = "Development"
	}
	
	var selectedConfig ConfigSettings
	for _, cfg := range configs {
		if cfg.EnvName == envType {
			selectedConfig = cfg
			break
		}
	}
	
	// ruleid: rule-deprecated-get-configuration
	result, err := appConfigClient.GetConfiguration(&oldappconfig.GetConfigurationInput{
		Application:   aws.String(selectedConfig.AppName),
		Environment:   aws.String(selectedConfig.EnvName),
		Configuration: aws.String(selectedConfig.ConfigName),
		ClientId:      aws.String(selectedConfig.ClientId),
	})
	
	if err != nil {
		fmt.Println("Error getting configuration:", err)
		return
	}
	
	fmt.Println("Configuration retrieved successfully")
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
func bad_case_14() {
	// Initialize AWS session
	sess := session.Must(session.NewSession())
	
	// Create AppConfig client
	svc := oldappconfig.New(sess)
	
	// Define a custom AppConfig interface
	type AppConfigGetter interface {
		GetConfig() ([]byte, error)
	}
	
	// Implement the interface with the deprecated API
	type DeprecatedAppConfigClient struct {
		client    *oldappconfig.AppConfig
		app       string
		env       string
		config    string
		clientId  string
	}
	
	func (c *DeprecatedAppConfigClient) GetConfig() ([]byte, error) {
		// ruleid: rule-deprecated-get-configuration
		result, err := c.client.GetConfiguration(&oldappconfig.GetConfigurationInput{
			Application:   aws.String(c.app),
			Environment:   aws.String(c.env),
			Configuration: aws.String(c.config),
			ClientId:      aws.String(c.clientId),
		})
		
		if err != nil {
			return nil, err
		}
		
		return result.Content, nil
	}
	
	// Create and use the client
	client := &DeprecatedAppConfigClient{
		client:    svc,
		app:       "FeatureFlags",
		env:       "Production",
		config:    "UIFeatures",
		clientId:  "WebClient",
	}
	
	content, err := client.GetConfig()
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	
	fmt.Println("Configuration content length:", len(content))
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
func bad_case_15() {
	// Initialize AWS session
	sess := session.Must(session.NewSession())
	
	// Create AppConfig client with custom retryer
	svc := oldappconfig.New(sess, &aws.Config{
		Retryer: aws.NewRetryer(aws.RetryerMaxNumRetries(10)),
	})
	
	// Define configuration parameters
	appName := "DataProcessingService"
	envName := "Production"
	configName := "ProcessingRules"
	clientId := "DataProcessor-" + appName
	
	// Create a function to fetch and cache configuration
	var cachedConfig []byte
	var cachedVersion string
	
	fetchConfig := func(force bool) ([]byte, error) {
		if !force && len(cachedConfig) > 0 {
			return cachedConfig, nil
		}
		
		input := &oldappconfig.GetConfigurationInput{
			Application:   aws.String(appName),
			Environment:   aws.String(envName),
			Configuration: aws.String(configName),
			ClientId:      aws.String(clientId),
		}
		
		if cachedVersion != "" {
			input.ClientConfigurationVersion = aws.String(cachedVersion)
		}
		
		// ruleid: rule-deprecated-get-configuration
		result, err := svc.GetConfiguration(input)
		if err != nil {
			return nil, err
		}
		
		if result.ConfigurationVersion != nil {
			cachedVersion = *result.ConfigurationVersion
		}
		
		cachedConfig = result.Content
		return cachedConfig, nil
	}
	
	// Use the function to get configuration
	config, err := fetchConfig(false)
	if err != nil {
		fmt.Println("Error fetching configuration:", err)
		return
	}
	
	fmt.Println("Configuration content length:", len(config))
}
// {/fact}

// True Negative Examples (Safe Code)

// {fact rule=guru-cfn-lint@v1.0 defects=0}
func good_case_1() {
	// Load the AWS SDK configuration
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		fmt.Println("Error loading AWS configuration:", err)
		return
	}
	
	// Create AppConfigData client using the recommended API
	client := appconfigdata.NewFromConfig(cfg)
	
	// Start a configuration session
	startSessionOutput, err := client.StartConfigurationSession(context.TODO(), &appconfigdata.StartConfigurationSessionInput{
		ApplicationIdentifier:          aws.String("MyApp"),
		EnvironmentIdentifier:          aws.String("Production"),
		ConfigurationProfileIdentifier: aws.String("MyConfig"),
	})
	
	if err != nil {
		fmt.Println("Error starting configuration session:", err)
		return
	}
	
	// ok: rule-deprecated-get-configuration
	configOutput, err := client.GetLatestConfiguration(context.TODO(), &appconfigdata.GetLatestConfigurationInput{
		ConfigurationToken: startSessionOutput.InitialConfigurationToken,
	})
	
	if err != nil {
		fmt.Println("Error getting latest configuration:", err)
		return
	}
	
	fmt.Println("Configuration content:", string(configOutput.Configuration))
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
func good_case_2() {
	// Load the AWS SDK configuration with region
	cfg, err := config.LoadDefaultConfig(context.TODO(), config.WithRegion("us-west-2"))
	if err != nil {
		fmt.Println("Failed to load AWS configuration:", err)
		return
	}
	
	// Create AppConfigData client
	client := appconfigdata.NewFromConfig(cfg)
	
	// Start a configuration session
	startSessionInput := &appconfigdata.StartConfigurationSessionInput{
		ApplicationIdentifier:          aws.String("OrderSystem"),
		EnvironmentIdentifier:          aws.String("Staging"),
		ConfigurationProfileIdentifier: aws.String("DatabaseSettings"),
	}
	
	sessionOutput, err := client.StartConfigurationSession(context.TODO(), startSessionInput)
	if err != nil {
		fmt.Println("Failed to start configuration session:", err)
		return
	}
	
	// ok: rule-deprecated-get-configuration
	configOutput, err := client.GetLatestConfiguration(context.TODO(), &appconfigdata.GetLatestConfigurationInput{
		ConfigurationToken: sessionOutput.InitialConfigurationToken,
	})
	
	if err != nil {
		fmt.Println("Failed to get latest configuration:", err)
		return
	}
	
	fmt.Println("Retrieved configuration with content type:", configOutput.ContentType)
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
func good_case_3() {
	// Load the AWS SDK configuration
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		fmt.Println("Error loading AWS configuration:", err)
		return
	}
	
	// Create AppConfigData client
	client := appconfigdata.NewFromConfig(cfg)
	
	// Start a configuration session
	startSessionOutput, err := client.StartConfigurationSession(context.TODO(), &appconfigdata.StartConfigurationSessionInput{
		ApplicationIdentifier:          aws.String("PaymentService"),
		EnvironmentIdentifier:          aws.String("Production"),
		ConfigurationProfileIdentifier: aws.String("ApiKeys"),
	})
	
	if err != nil {
		fmt.Println("Error starting configuration session:", err)
		return
	}
	
	// Get configuration with retry logic
	var configToken string = startSessionOutput.InitialConfigurationToken
	var configOutput *appconfigdata.GetLatestConfigurationOutput
	
	for i := 0; i < 3; i++ {
		// ok: rule-deprecated-get-configuration
		configOutput, err = client.GetLatestConfiguration(context.TODO(), &appconfigdata.GetLatestConfigurationInput{
			ConfigurationToken: configToken,
		})
		
		if err == nil {
			configToken = configOutput.NextPollConfigurationToken
			break
		}
		
		fmt.Printf("Attempt %d failed: %v\n", i+1, err)
	}
	
	if err != nil {
		fmt.Println("All attempts to get configuration failed")
		return
	}
	
	fmt.Println("Configuration retrieved successfully")
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
func good_case_4() {
	// Create a custom AppConfigData client interface for testing
	type AppConfigDataClientInterface interface {
		StartConfigurationSession(context.Context, *appconfigdata.StartConfigurationSessionInput, ...func(*appconfigdata.Options)) (*appconfigdata.StartConfigurationSessionOutput, error)
		GetLatestConfiguration(context.Context, *appconfigdata.GetLatestConfigurationInput, ...func(*appconfigdata.Options)) (*appconfigdata.GetLatestConfigurationOutput, error)
	}
	
	// Load the AWS SDK configuration
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		fmt.Println("Error loading AWS configuration:", err)
		return
	}
	
	// Create AppConfigData client that implements the interface
	var client AppConfigDataClientInterface = appconfigdata.NewFromConfig(cfg)
	
	// Start a configuration session
	sessionOutput, err := client.StartConfigurationSession(context.TODO(), &appconfigdata.StartConfigurationSessionInput{
		ApplicationIdentifier:          aws.String("NotificationSystem"),
		EnvironmentIdentifier:          aws.String("Development"),
		ConfigurationProfileIdentifier: aws.String("EmailTemplates"),
	})
	
	if err != nil {
		fmt.Println("Error starting configuration session:", err)
		return
	}
	
	// ok: rule-deprecated-get-configuration
	configOutput, err := client.GetLatestConfiguration(context.TODO(), &appconfigdata.GetLatestConfigurationInput{
		ConfigurationToken: sessionOutput.InitialConfigurationToken,
	})
	
	if err != nil {
		fmt.Println("Error getting latest configuration:", err)
		return
	}
	
	fmt.Println("Configuration content length:", len(configOutput.Configuration))
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
func good_case_5(ctx context.Context, cfg aws.Config) {
	// Using the recommended API with a config passed as a parameter
	client := appconfigdata.NewFromConfig(cfg)
	
	// Start a configuration session
	sessionOutput, err := client.StartConfigurationSession(ctx, &appconfigdata.StartConfigurationSessionInput{
		ApplicationIdentifier:          aws.String("UserManagement"),
		EnvironmentIdentifier:          aws.String("Production"),
		ConfigurationProfileIdentifier: aws.String("UserRoles"),
	})
	
	if err != nil {
		fmt.Println("Failed to start configuration session:", err)
		return
	}
	
	// ok: rule-deprecated-get-configuration
	configOutput, err := client.GetLatestConfiguration(ctx, &appconfigdata.GetLatestConfigurationInput{
		ConfigurationToken: sessionOutput.InitialConfigurationToken,
	})
	
	if err != nil {
		fmt.Println("Failed to get latest configuration:", err)
		return
	}
	
	fmt.Println("Configuration retrieved successfully, content length:", len(configOutput.Configuration))
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
func good_case_6() {
	// Load the AWS SDK configuration with profile
	cfg, err := config.LoadDefaultConfig(context.TODO(), config.WithSharedConfigProfile("production"))
	if err != nil {
		fmt.Println("Error loading AWS configuration:", err)
		return
	}
	
	// Create AppConfigData client
	client := appconfigdata.NewFromConfig(cfg)
	
	// Define configuration parameters
	app := "LoggingService"
	env := "Production"
	config := "LogLevels"
	
	// Start a configuration session
	sessionOutput, err := client.StartConfigurationSession(context.TODO(), &appconfigdata.StartConfigurationSessionInput{
		ApplicationIdentifier:          &app,
		EnvironmentIdentifier:          &env,
		ConfigurationProfileIdentifier: &config,
	})
	
	if err != nil {
		fmt.Println("Error starting configuration session:", err)
		return
	}
	
	// ok: rule-deprecated-get-configuration
	configOutput, err := client.GetLatestConfiguration(context.TODO(), &appconfigdata.GetLatestConfigurationInput{
		ConfigurationToken: sessionOutput.InitialConfigurationToken,
	})
	
	if err != nil {
		fmt.Println("Error getting latest configuration:", err)
		return
	}
	
	fmt.Println("Configuration retrieved successfully:", string(configOutput.Configuration))
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
func good_case_7() {
	// Load the AWS SDK configuration with custom endpoint
	cfg, err := config.LoadDefaultConfig(context.TODO(),
		config.WithEndpointResolverWithOptions(aws.EndpointResolverWithOptionsFunc(
			func(service, region string, options ...interface{}) (aws.Endpoint, error) {
				if service == "appconfigdata" {
					return aws.Endpoint{
						URL: "https://appconfigdata.us-east-1.amazonaws.com",
					}, nil
				}
				return aws.Endpoint{}, fmt.Errorf("unknown endpoint for %s in %s", service, region)
			})),
	)
	if err != nil {
		fmt.Println("Error loading AWS configuration:", err)
		return
	}
	
	// Create AppConfigData client
	client := appconfigdata.NewFromConfig(cfg)
	
	// Start a configuration session
	sessionOutput, err := client.StartConfigurationSession(context.TODO(), &appconfigdata.StartConfigurationSessionInput{
		ApplicationIdentifier:          aws.String("AnalyticsService"),
		EnvironmentIdentifier:          aws.String("Production"),
		ConfigurationProfileIdentifier: aws.String("TrackingConfig"),
	})
	
	if err != nil {
		fmt.Println("Error starting configuration session:", err)
		return
	}
	
	// ok: rule-deprecated-get-configuration
	configOutput, err := client.GetLatestConfiguration(context.TODO(), &appconfigdata.GetLatestConfigurationInput{
		ConfigurationToken: sessionOutput.InitialConfigurationToken,
	})
	
	if err != nil {
		fmt.Println("Error getting latest configuration:", err)
		return
	}
	
	fmt.Println("Configuration content type:", configOutput.ContentType)
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
func good_case_8() {
	// Load the AWS SDK configuration
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		fmt.Println("Error loading AWS configuration:", err)
		return
	}
	
	// Create AppConfigData client
	appConfigDataClient := appconfigdata.NewFromConfig(cfg)
	
	// Function to get configuration
	getConfig := func(ctx context.Context, app, env, config string) ([]byte, error) {
		// Start a configuration session
		sessionOutput, err := appConfigDataClient.StartConfigurationSession(ctx, &appconfigdata.StartConfigurationSessionInput{
			ApplicationIdentifier:          aws.String(app),
			EnvironmentIdentifier:          aws.String(env),
			ConfigurationProfileIdentifier: aws.String(config),
		})
		
		if err != nil {
			return nil, fmt.Errorf("failed to start configuration session: %w", err)
		}
		
		// ok: rule-deprecated-get-configuration
		configOutput, err := appConfigDataClient.GetLatestConfiguration(ctx, &appconfigdata.GetLatestConfigurationInput{
			ConfigurationToken: sessionOutput.InitialConfigurationToken,
		})
		
		if err != nil {
			return nil, fmt.Errorf("failed to get latest configuration: %w", err)
		}
		
		return configOutput.Configuration, nil
	}
	
	// Use the function to get configuration
	content, err := getConfig(context.TODO(), "SearchService", "Production", "SearchSettings")
	if err != nil {
		fmt.Println("Error getting configuration:", err)
		return
	}
	
	fmt.Println("Configuration content length:", len(content))
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
func good_case_9() {
	// Load the AWS SDK configuration
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		fmt.Println("Error loading AWS configuration:", err)
		return
	}
	
	// Create AppConfigData client
	client := appconfigdata.NewFromConfig(cfg)
	
	// Define configuration parameters from environment variables
	app := os.Getenv("APP_NAME")
	if app == "" {
		app = "DefaultApp"
	}
	
	env := os.Getenv("APP_ENV")
	if env == "" {
		env = "Development"
	}
	
	config := os.Getenv("CONFIG_NAME")
	if config == "" {
		config = "DefaultConfig"
	}
	
	// Start a configuration session
	sessionOutput, err := client.StartConfigurationSession(context.TODO(), &appconfigdata.StartConfigurationSessionInput{
		ApplicationIdentifier:          aws.String(app),
		EnvironmentIdentifier:          aws.String(env),
		ConfigurationProfileIdentifier: aws.String(config),
	})
	
	if err != nil {
		fmt.Println("Error starting configuration session:", err)
		return
	}
	
	// ok: rule-deprecated-get-configuration
	configOutput, err := client.GetLatestConfiguration(context.TODO(), &appconfigdata.GetLatestConfigurationInput{
		ConfigurationToken: sessionOutput.InitialConfigurationToken,
	})
	
	if err != nil {
		fmt.Println("Error getting latest configuration:", err)
		return
	}
	
	fmt.Println("Configuration content:", string(configOutput.Configuration))
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
func good_case_10() {
	// Load the AWS SDK configuration with region
	cfg, err := config.LoadDefaultConfig(context.TODO(), config.WithRegion("eu-west-1"))
	if err != nil {
		fmt.Println("Error loading AWS configuration:", err)
		return
	}
	
	// Create AppConfigData client
	client := appconfigdata.NewFromConfig(cfg)
	
	// Start a configuration session
	sessionOutput, err := client.StartConfigurationSession(context.TODO(), &appconfigdata.StartConfigurationSessionInput{
		ApplicationIdentifier:          aws.String("RecommendationEngine"),
		EnvironmentIdentifier:          aws.String("Production"),
		ConfigurationProfileIdentifier: aws.String("AlgorithmSettings"),
	})
	
	if err != nil {
		fmt.Println("Failed to start configuration session:", err)
		return
	}
	
	// ok: rule-deprecated-get-configuration
	configOutput, err := client.GetLatestConfiguration(context.TODO(), &appconfigdata.GetLatestConfigurationInput{
		ConfigurationToken: sessionOutput.InitialConfigurationToken,
	})
	
	if err != nil {
		fmt.Println("Failed to get latest configuration:", err)
		return
	}
	
	// Process the configuration
	fmt.Println("Configuration content length:", len(configOutput.Configuration))
	fmt.Println("Configuration content type:", configOutput.ContentType)
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
func good_case_11() {
	// Load the AWS SDK configuration
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		fmt.Println("Error loading AWS configuration:", err)
		return
	}
	
	// Create AppConfigData client
	appConfigDataClient := appconfigdata.NewFromConfig(cfg)
	
	// Define a wrapper function for getting configuration
	getAppConfig := func(ctx context.Context, appName, envName, configName string) ([]byte, string, error) {
		// Start a configuration session
		sessionOutput, err := appConfigDataClient.StartConfigurationSession(ctx, &appconfigdata.StartConfigurationSessionInput{
			ApplicationIdentifier:          aws.String(appName),
			EnvironmentIdentifier:          aws.String(envName),
			ConfigurationProfileIdentifier: aws.String(configName),
		})
		
		if err != nil {
			return nil, "", fmt.Errorf("failed to start configuration session: %w", err)
		}
		
		// ok: rule-deprecated-get-configuration
		configOutput, err := appConfigDataClient.GetLatestConfiguration(ctx, &appconfigdata.GetLatestConfigurationInput{
			ConfigurationToken: sessionOutput.InitialConfigurationToken,
		})
		
		if err != nil {
			return nil, "", fmt.Errorf("failed to get latest configuration: %w", err)
		}
		
		return configOutput.Configuration, configOutput.ContentType, nil
	}
	
	// Use the wrapper function
	content, contentType, err := getAppConfig(context.TODO(), "CatalogService", "Staging", "ProductCatalog")
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	
	fmt.Printf("Retrieved configuration with content type %s and %d bytes\n", contentType, len(content))
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
func good_case_12() {
	// Use the AWS AppConfig Agent client
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		fmt.Println("Error loading AWS configuration:", err)
		return
	}
	
	// Create AppConfig Agent client
	client := appconfigagent.NewFromConfig(cfg)
	
	// ok: rule-deprecated-get-configuration
	result, err := client.GetLatestConfiguration(context.TODO(), &appconfigagent.GetLatestConfigurationInput{
		ConfigurationName: aws.String("InventoryRules"),
	})
	
	if err != nil {
		fmt.Println("Error getting latest configuration:", err)
		return
	}
	
	fmt.Println("Configuration content size:", len(result.Configuration))
	fmt.Println("Configuration content type:", result.ContentType)
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
func good_case_13() {
	// Load the AWS SDK configuration
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		fmt.Println("Error loading AWS configuration:", err)
		return
	}
	
	// Create AppConfigData client
	client := appconfigdata.NewFromConfig(cfg)
	
	// Define a struct to hold configuration settings
	type ConfigSettings struct {
		AppName    string
		EnvName    string
		ConfigName string
	}
	
	// Create settings for different environments
	configs := []ConfigSettings{
		{
			AppName:    "AuthService",
			EnvName:    "Development",
			ConfigName: "AuthSettings",
		},
		{
			AppName:    "AuthService",
			EnvName:    "Production",
			ConfigName: "AuthSettings",
		},
	}
	
	// Get configuration for the current environment
	envType := os.Getenv("ENV_TYPE")
	if envType == "" {
		envType = "Development"
	}
	
	var selectedConfig ConfigSettings
	for _, cfg := range configs {
		if cfg.EnvName == envType {
			selectedConfig = cfg
			break
		}
	}
	
	// Start a configuration session
	sessionOutput, err := client.StartConfigurationSession(context.TODO(), &appconfigdata.StartConfigurationSessionInput{
		ApplicationIdentifier:          aws.String(selectedConfig.AppName),
		EnvironmentIdentifier:          aws.String(selectedConfig.EnvName),
		ConfigurationProfileIdentifier: aws.String(selectedConfig.ConfigName),
	})
	
	if err != nil {
		fmt.Println("Error starting configuration session:", err)
		return
	}
	
	// ok: rule-deprecated-get-configuration
	configOutput, err := client.GetLatestConfiguration(context.TODO(), &appconfigdata.GetLatestConfigurationInput{
		ConfigurationToken: sessionOutput.InitialConfigurationToken,
	})
	
	if err != nil {
		fmt.Println("Error getting latest configuration:", err)
		return
	}
	
	fmt.Println("Configuration retrieved successfully")
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
func good_case_14() {
	// Load the AWS SDK configuration
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		fmt.Println("Error loading AWS configuration:", err)
		return
	}
	
	// Define a custom AppConfig interface
	type AppConfigGetter interface {
		GetConfig(ctx context.Context) ([]byte, error)
	}
	
	// Implement the interface with the recommended API
	type RecommendedAppConfigClient struct {
		client    *appconfigdata.Client
		app       string
		env       string
		config    string
	}
	
	func (c *RecommendedAppConfigClient) GetConfig(ctx context.Context) ([]byte, error) {
		// Start a configuration session
		sessionOutput, err := c.client.StartConfigurationSession(ctx, &appconfigdata.StartConfigurationSessionInput{
			ApplicationIdentifier:          aws.String(c.app),
			EnvironmentIdentifier:          aws.String(c.env),
			ConfigurationProfileIdentifier: aws.String(c.config),
		})
		
		if err != nil {
			return nil, fmt.Errorf("failed to start configuration session: %w", err)
		}
		
		// ok: rule-deprecated-get-configuration
		configOutput, err := c.client.GetLatestConfiguration(ctx, &appconfigdata.GetLatestConfigurationInput{
			ConfigurationToken: sessionOutput.InitialConfigurationToken,
		})
		
		if err != nil {
			return nil, fmt.Errorf("failed to get latest configuration: %w", err)
		}
		
		return configOutput.Configuration, nil
	}
	
	// Create and use the client
	client := &RecommendedAppConfigClient{
		client:    appconfigdata.NewFromConfig(cfg),
		app:       "FeatureFlags",
		env:       "Production",
		config:    "UIFeatures",
	}
	
	content, err := client.GetConfig(context.TODO())
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	
	fmt.Println("Configuration content length:", len(content))
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
func good_case_15() {
	// Load the AWS SDK configuration
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		fmt.Println("Error loading AWS configuration:", err)
		return
	}
	
	// Create AppConfigData client
	client := appconfigdata.NewFromConfig(cfg)
	
	// Define configuration parameters
	appName := "DataProcessingService"
	envName := "Production"
	configName := "ProcessingRules"
	
	// Create a function to fetch and cache configuration
	var cachedConfig []byte
	var cachedToken string
	
	fetchConfig := func(ctx context.Context, force bool) ([]byte, error) {
		if !force && len(cachedConfig) > 0 && cachedToken != "" {
			// Use cached token for subsequent requests
			// ok: rule-deprecated-get-configuration
			configOutput, err := client.GetLatestConfiguration(ctx, &appconfigdata.GetLatestConfigurationInput{
				ConfigurationToken: cachedToken,
			})
			
			if err == nil && len(configOutput.Configuration) > 0 {
				cachedConfig = configOutput.Configuration
				cachedToken = configOutput.NextPollConfigurationToken
				return cachedConfig, nil
			}
		}
		
		// Start a new configuration session
		sessionOutput, err := client.StartConfigurationSession(ctx, &appconfigdata.StartConfigurationSessionInput{
			ApplicationIdentifier:          aws.String(appName),
			EnvironmentIdentifier:          aws.String(envName),
			ConfigurationProfileIdentifier: aws.String(configName),
		})
		
		if err != nil {
			return nil, fmt.Errorf("failed to start configuration session: %w", err)
		}
		
		// ok: rule-deprecated-get-configuration
		configOutput, err := client.GetLatestConfiguration(ctx, &appconfigdata.GetLatestConfigurationInput{
			ConfigurationToken: sessionOutput.InitialConfigurationToken,
		})
		
		if err != nil {
			return nil, fmt.Errorf("failed to get latest configuration: %w", err)
		}
		
		cachedConfig = configOutput.Configuration
		cachedToken = configOutput.NextPollConfigurationToken
		return cachedConfig, nil
	}
	
	// Use the function to get configuration
	config, err := fetchConfig(context.TODO(), false)
	if err != nil {
		fmt.Println("Error fetching configuration:", err)
		return
	}
	
	fmt.Println("Configuration content length:", len(config))
}
// {/fact}

func main() {
	// This is just a placeholder main function
	fmt.Println("AWS AppConfig examples")
}