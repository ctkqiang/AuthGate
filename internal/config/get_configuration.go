package config

import (
	"authgate/internal/utilities"
	"strings"

	"github.com/BurntSushi/toml"
)

var config map[string]interface{}

func LoadConfigurationFile(path string) {
	if _, err := toml.DecodeFile(path, &config); err != nil {
		utilities.LogProgress("Configuration loading failed", "DecodeFile", err.Error())
		return
	}

	utilities.LogProgress(
		"Configuration loaded successfully",
		"DecodeFile",
		path,
	)
}

func GetValue(key string) interface{} {
	var current interface{} = config
	if config == nil {
		return nil
	}

	keys := strings.Split(key, ".")

	for i, k := range keys {
		switch m := current.(type) {
		case map[string]interface{}:
			val, ok := m[k]
			if !ok {
				return nil
			}
			if i == len(keys)-1 {
				return val
			}
			current = val
		default:
			return nil
		}
	}
	return nil
}
